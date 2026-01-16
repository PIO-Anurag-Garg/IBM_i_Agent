# IBM i Performance Agent - Version 7.6
# Targets IBM i 7.6 with enhanced services, user data access, and program source reading

import os
import re
import sys
import json
from textwrap import dedent
from typing import Any, Dict, Optional, List, Sequence, Tuple

from dotenv import load_dotenv
from mapepire_python import connect
from pep249 import QueryParameters

from agno.agent import Agent
from agno.models.openrouter import OpenRouter
from agno.tools import tool

# =============================================================================
# ENV / CONNECTION
# =============================================================================

load_dotenv()


def _require_env(name: str, default: Optional[str] = None) -> str:
    """Fetch required environment variable or default; raise helpful error if missing."""
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Set it in your shell or in a .env mechanism."
        )
    return value


def get_ibmi_credentials() -> Dict[str, Any]:
    """
    Mapepire connection details.
    Mapepire server default port is 8076.
    """
    creds: Dict[str, Any] = {
        "host": _require_env("IBMI_HOST"),
        "port": int(_require_env("IBMI_PORT", "8076")),
        "user": _require_env("IBMI_USER"),
        "password": _require_env("IBMI_PASSWORD"),
    }

    # Optional: allow TLS self-signed certs (Mapepire option)
    ignore_unauth = os.getenv("IBMI_IGNORE_UNAUTHORIZED", "").strip().lower()
    if ignore_unauth in {"1", "true", "yes", "y"}:
        creds["ignoreUnauthorized"] = True

    return creds


def format_mapepire_result(result: Any) -> str:
    """Return readable JSON for the agent to interpret."""
    try:
        return json.dumps(result, indent=2, default=str)
    except Exception:
        return str(result)


def run_sql_statement(
    sql: str,
    parameters: Optional[QueryParameters] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> str:
    """Execute SQL and return formatted results text."""
    creds = creds or get_ibmi_credentials()

    with connect(creds) as conn:
        with conn.execute(sql, parameters=parameters) as cur:
            if getattr(cur, "has_results", False):
                raw = cur.fetchall()
                if isinstance(raw, dict) and "data" in raw:
                    return format_mapepire_result(raw["data"])
                return format_mapepire_result(raw)
            return "SQL executed successfully. No results returned."


def run_sql_raw(
    sql: str,
    parameters: Optional[QueryParameters] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> Any:
    """
    Execute SQL and return the raw python object.
    Useful for capability detection where we need to inspect structured results.
    """
    creds = creds or get_ibmi_credentials()

    with connect(creds) as conn:
        with conn.execute(sql, parameters=parameters) as cur:
            if getattr(cur, "has_results", False):
                return cur.fetchall()
            return None


def _as_rows(raw: Any) -> List[Dict[str, Any]]:
    """
    Best effort conversion to list-of-dict rows for Mapepire outputs.
    """
    if isinstance(raw, dict) and "data" in raw and isinstance(raw["data"], list):
        return raw["data"]
    if isinstance(raw, list):
        # expecting list[dict]
        return raw
    return []


# =============================================================================
# SAFETY HELPERS (Prevent SQL injection; allow only safe identifiers & SELECT tools)
# =============================================================================

_SAFE_IDENT = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)
_SAFE_SCHEMA = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)
_FORBIDDEN_SQL_TOKENS = re.compile(
    r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bMERGE\b|\bDROP\b|\bALTER\b|\bCREATE\b|\bCALL\b|\bGRANT\b|\bREVOKE\b|\bRUN\b|\bCL:\b|\bQCMDEXC\b)",
    re.IGNORECASE,
)

# Base system schemas (always allowed)
_ALLOWED_SCHEMAS = {"QSYS2", "SYSTOOLS", "SYSIBM", "QSYS", "INFORMATION_SCHEMA"}

# Expand with user-defined schemas from environment
user_schemas = os.getenv("ALLOWED_USER_SCHEMAS", "").strip()
if user_schemas:
    user_schemas_list = [s.strip().upper() for s in user_schemas.split(",") if s.strip()]
    _ALLOWED_SCHEMAS.update(user_schemas_list)
    print(f"[SECURITY] User schemas enabled: {', '.join(user_schemas_list)}", file=sys.stderr)

# Store original system schemas for reference
_SYSTEM_SCHEMAS = {"QSYS2", "SYSTOOLS", "SYSIBM", "QSYS", "INFORMATION_SCHEMA"}
_USER_SCHEMAS = _ALLOWED_SCHEMAS - _SYSTEM_SCHEMAS


def _safe_ident(value: str, what: str = "identifier") -> str:
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()


def _safe_ident_or_special(value: str, what: str = "identifier") -> str:
    """
    Like _safe_ident but also allows IBM i special values like *ALL, *ALLSIMPLE, *LIBL, etc.
    Used for library parameters that accept special values in QSYS2.OBJECT_STATISTICS.
    """
    v = (value or "").strip()
    if not v:
        raise ValueError(f"Invalid {what}: {value!r}")
    # Allow normal identifiers OR IBM i special values starting with *
    if v.startswith("*"):
        # Validate special value format: *WORD (alphanumeric after asterisk)
        if not re.match(r"^\*[A-Z0-9_]+$", v, re.IGNORECASE):
            raise ValueError(f"Invalid {what}: {value!r}")
        return v.upper()
    # Otherwise use normal identifier validation
    if not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()


def _safe_schema(value: str) -> str:
    v = (value or "").strip()
    if not v or not _SAFE_SCHEMA.match(v):
        raise ValueError(f"Invalid schema: {value!r}")
    return v.upper()


def _safe_csv_idents(value: str, what: str = "list") -> str:
    parts = [p.strip() for p in (value or "").split(",") if p.strip()]
    if not parts:
        return ""
    norm = [_safe_ident(p, what=what) for p in parts]
    return ",".join(norm)


def _safe_limit(n: int, default: int = 10, max_n: int = 5000) -> int:
    try:
        n = int(n)
    except Exception:
        return default
    return max(1, min(n, max_n))


def _looks_like_safe_select(sql: str) -> None:
    """
    Guardrail:
    - Must start with SELECT/WITH
    - Must not contain forbidden tokens
    - Must not contain multiple statements (;)
    - Must reference only allowed schemas (best effort heuristic)
    """
    s = (sql or "").strip()
    if not s:
        raise ValueError("Empty SQL is not allowed.")

    head = s.lstrip().upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise ValueError("Only SELECT/WITH statements are allowed.")

    if ";" in s:
        raise ValueError("Multiple statements are not allowed (no semicolons).")

    if _FORBIDDEN_SQL_TOKENS.search(s):
        raise ValueError("Forbidden SQL operation detected. Only read-only queries are allowed.")

    schema_refs = set(re.findall(r"\b([A-Z0-9_#$@]{1,128})\s*\.", s.upper()))
    for sch in schema_refs:
        if sch in {"TABLE", "VALUES", "LATERAL"}:
            continue
        if sch not in _ALLOWED_SCHEMAS:
            raise ValueError(
                f"Query references non-allowed schema '{sch}'. "
                f"Allowed schemas: {sorted(_ALLOWED_SCHEMAS)}"
            )


def run_select(sql: str, parameters: Optional[QueryParameters] = None) -> str:
    """Execute safe read-only SELECT/WITH query with guardrails and friendly errors."""
    try:
        _looks_like_safe_select(sql)
        return run_sql_statement(sql, parameters=parameters)
    except ValueError as e:
        # Validation errors - return clean error message without stack trace
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR executing SQL Service/cat query. Details: {type(e).__name__}: {e}"


# =============================================================================
# IBM i 7.6 SERVICE DISCOVERY (from 7.3 compatibility layer)
# =============================================================================

SERVICES_INFO_EXISTS_SQL = """
SELECT 1 AS X
FROM QSYS2.SERVICES_INFO
WHERE SERVICE_SCHEMA_NAME = ?
  AND SERVICE_NAME = ?
FETCH FIRST 1 ROWS ONLY
"""

_services_cache: Dict[Tuple[str, str], bool] = {}


def service_exists(schema: str, service_name: str) -> bool:
    """
    Check for service presence via QSYS2.SERVICES_INFO.
    This catalog is the supported way to determine IBM i Services availability.
    """
    sch = _safe_schema(schema)
    svc = _safe_ident(service_name, what="service_name")
    key = (sch, svc)
    if key in _services_cache:
        return _services_cache[key]

    try:
        raw = run_sql_raw(SERVICES_INFO_EXISTS_SQL, parameters=[sch, svc])
        rows = _as_rows(raw)
        ok = len(rows) > 0
    except Exception:
        ok = False

    _services_cache[key] = ok
    return ok


# =============================================================================
# SQL TEMPLATES (IBM i Services + Catalogs)
# =============================================================================

SYSTEM_STATUS_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS(RESET_STATISTICS => 'NO', DETAILED_INFO => 'ALL')) X"
SYSTEM_ACTIVITY_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_ACTIVITY_INFO())"

SERVICES_SEARCH_SQL = """
SELECT SERVICE_CATEGORY, SERVICE_SCHEMA_NAME, SERVICE_NAME, SQL_OBJECT_TYPE, EARLIEST_POSSIBLE_RELEASE
FROM QSYS2.SERVICES_INFO
WHERE (UPPER(SERVICE_NAME) LIKE UPPER(?) OR UPPER(SERVICE_CATEGORY) LIKE UPPER(?))
ORDER BY SERVICE_CATEGORY, SERVICE_SCHEMA_NAME, SERVICE_NAME
FETCH FIRST ? ROWS ONLY
"""

TOP_CPU_JOBS_SQL = """
SELECT JOB_NAME,
       AUTHORIZATION_NAME AS USER_NAME,
       SUBSYSTEM,
       JOB_STATUS,
       JOB_TYPE,
       CPU_TIME,
       TEMPORARY_STORAGE,
       TOTAL_DISK_IO_COUNT,
       TOTAL_DISK_IO_TIME,
       SQL_STATEMENT_TEXT
FROM TABLE(
  QSYS2.ACTIVE_JOB_INFO(
    SUBSYSTEM_LIST_FILTER => ?,
    CURRENT_USER_LIST_FILTER => ?,
    DETAILED_INFO => 'ALL'
  )
) X
ORDER BY CPU_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

MSGW_JOBS_SQL = """
SELECT JOB_NAME,
       AUTHORIZATION_NAME AS USER_NAME,
       SUBSYSTEM,
       FUNCTION,
       JOB_STATUS,
       CPU_TIME,
       MESSAGE_ID,
       MESSAGE_TEXT
FROM TABLE(QSYS2.ACTIVE_JOB_INFO(DETAILED_INFO => 'ALL')) X
WHERE JOB_STATUS = 'MSGW'
ORDER BY SUBSYSTEM, CPU_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

ASP_INFO_SQL = "SELECT * FROM QSYS2.ASP_INFO ORDER BY ASP_NUMBER"

DISK_HOTSPOTS_SQL = """
SELECT ASP_NUMBER,
       RESOURCE_NAME,
       SERIAL_NUMBER,
       HARDWARE_STATUS,
       RESOURCE_STATUS,
       PERCENT_USED,
       UNIT_SPACE_AVAILABLE_GB,
       TOTAL_READ_REQUESTS,
       TOTAL_WRITE_REQUESTS
FROM QSYS2.SYSDISKSTAT
ORDER BY PERCENT_USED DESC
FETCH FIRST ? ROWS ONLY
"""

NETSTAT_SUMMARY_SQL = """
SELECT LOCAL_ADDRESS,
       LOCAL_PORT,
       REMOTE_ADDRESS,
       REMOTE_PORT,
       CONNECTION_STATE,
       IDLE_TIME
FROM QSYS2.NETSTAT_INFO
ORDER BY IDLE_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

QSYSOPR_RECENT_MSGS_SQL = """
SELECT MSG_TIME,
       MSGID,
       MSG_TYPE,
       SEVERITY,
       CAST(MSG_TEXT AS VARCHAR(1024)) AS MSG_TEXT,
       FROM_USER,
       FROM_JOB,
       FROM_PGM
FROM QSYS2.MESSAGE_QUEUE_INFO
WHERE MSGQ_LIB = 'QSYS'
  AND MSGQ_NAME = 'QSYSOPR'
ORDER BY MSG_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

OUTQ_HOTSPOTS_SQL = """
SELECT OUTPUT_QUEUE_LIBRARY_NAME AS OUTQ_LIB,
       OUTPUT_QUEUE_NAME AS OUTQ,
       NUMBER_OF_FILES,
       OUTPUT_QUEUE_STATUS,
       NUMBER_OF_WRITERS
FROM QSYS2.OUTPUT_QUEUE_INFO
ORDER BY NUMBER_OF_FILES DESC
FETCH FIRST ? ROWS ONLY
"""

ENDED_JOB_INFO_SQL = """
SELECT *
FROM TABLE(SYSTOOLS.ENDED_JOB_INFO())
ORDER BY END_TIMESTAMP DESC
FETCH FIRST ? ROWS ONLY
"""

JOB_QUEUE_ENTRIES_SQL = """
SELECT *
FROM TABLE(SYSTOOLS.JOB_QUEUE_ENTRIES())
ORDER BY JOB_QUEUE_NAME, JOB_QUEUE_LIBRARY
FETCH FIRST ? ROWS ONLY
"""

USER_STORAGE_SQL = """
SELECT AUTHORIZATION_NAME,
       STORAGE_USED,
       TEMPORARY_STORAGE_USED,
       NUMBER_OF_OBJECTS
FROM QSYS2.USER_STORAGE
ORDER BY STORAGE_USED DESC
FETCH FIRST ? ROWS ONLY
"""

IFS_OBJECT_STATISTICS_SQL = """
SELECT PATH_NAME,
       OBJECT_TYPE,
       DATA_SIZE,
       CREATE_TIMESTAMP,
       CHANGE_TIMESTAMP
FROM TABLE(QSYS2.IFS_OBJECT_STATISTICS(?)) X
ORDER BY DATA_SIZE DESC
FETCH FIRST ? ROWS ONLY
"""

OBJECT_CHANGED_RECENTLY_SQL = """
SELECT SYSTEM_OBJECT_SCHEMA,
       SYSTEM_OBJECT_NAME,
       OBJECT_TYPE,
       TEXT_DESCRIPTION,
       CREATE_TIMESTAMP,
       CHANGE_TIMESTAMP
FROM QSYS2.OBJECT_STATISTICS
WHERE CHANGE_TIMESTAMP >= (CURRENT_TIMESTAMP - ? DAYS)
ORDER BY CHANGE_TIMESTAMP DESC
FETCH FIRST ? ROWS ONLY
"""

PTF_IPL_REQUIRED_SQL = """
SELECT PTF_ID,
       PRODUCT_ID,
       PRODUCT_OPTION,
       PTF_STATUS,
       PTF_ACTION_REQUIRED,
       LOADED_TIMESTAMP
FROM QSYS2.PTF_INFO
WHERE PTF_ACTION_REQUIRED = 'IPL'
ORDER BY LOADED_TIMESTAMP DESC
FETCH FIRST ? ROWS ONLY
"""

SOFTWARE_PRODUCT_INFO_SQL = """
SELECT PRODUCT_ID,
       PRODUCT_OPTION,
       RELEASE_LEVEL,
       INSTALLED,
       LOAD_STATE,
       TEXT_DESCRIPTION
FROM QSYS2.SOFTWARE_PRODUCT_INFO
WHERE (? IS NULL OR PRODUCT_ID = ?)
ORDER BY PRODUCT_ID, PRODUCT_OPTION
FETCH FIRST ? ROWS ONLY
"""

LICENSE_INFO_SQL = """
SELECT *
FROM QSYS2.LICENSE_INFO
ORDER BY PRODUCT_ID
FETCH FIRST ? ROWS ONLY
"""

USER_INFO_BASIC_SQL = """
SELECT *
FROM QSYS2.USER_INFO_BASIC
ORDER BY AUTHORIZATION_NAME
FETCH FIRST ? ROWS ONLY
"""

USER_INFO_PRIVILEGED_SQL = """
SELECT AUTHORIZATION_NAME,
       STATUS,
       USER_CLASS_NAME,
       SPECIAL_AUTHORITIES,
       GROUP_PROFILE_NAME,
       OWNER,
       HOME_DIRECTORY,
       TEXT_DESCRIPTION,
       PASSWORD_CHANGE_DATE,
       INVALID_SIGNON_ATTEMPTS
FROM QSYS2.USER_INFO
ORDER BY AUTHORIZATION_NAME
FETCH FIRST ? ROWS ONLY
"""

PUBLIC_ALL_OBJECTS_SQL = """
SELECT *
FROM QSYS2.OBJECT_PRIVILEGES
WHERE AUTHORIZATION_NAME = '*PUBLIC'
  AND OBJECT_AUTHORITY = '*ALL'
ORDER BY SYSTEM_OBJECT_SCHEMA, SYSTEM_OBJECT_NAME, OBJECT_TYPE
FETCH FIRST ? ROWS ONLY
"""

OBJECT_PRIVILEGES_FOR_OBJECT_SQL = """
SELECT *
FROM QSYS2.OBJECT_PRIVILEGES
WHERE SYSTEM_OBJECT_SCHEMA = ?
  AND SYSTEM_OBJECT_NAME = ?
ORDER BY AUTHORIZATION_NAME
FETCH FIRST ? ROWS ONLY
"""

AUTH_LIST_INFO_SQL = """
SELECT *
FROM QSYS2.AUTHORIZATION_LIST_INFO
ORDER BY AUTHORIZATION_LIST_LIBRARY, AUTHORIZATION_LIST_NAME
FETCH FIRST ? ROWS ONLY
"""

AUTH_LIST_ENTRIES_SQL = """
SELECT *
FROM QSYS2.AUTHORIZATION_LIST_ENTRIES
WHERE AUTHORIZATION_LIST_LIBRARY = ?
  AND AUTHORIZATION_LIST_NAME = ?
ORDER BY USER_PROFILE_NAME
FETCH FIRST ? ROWS ONLY
"""

PLAN_CACHE_TOP_SQL = """
SELECT *
FROM QSYS2.PLAN_CACHE_STATEMENT
ORDER BY TOTAL_ELAPSED_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

PLAN_CACHE_ERRORS_SQL = """
SELECT *
FROM QSYS2.PLAN_CACHE_STATEMENT
WHERE STATEMENT_TEXT IS NOT NULL
  AND (TOTAL_ERROR_COUNT > 0 OR TOTAL_WARNING_COUNT > 0)
ORDER BY TOTAL_ERROR_COUNT DESC, TOTAL_WARNING_COUNT DESC
FETCH FIRST ? ROWS ONLY
"""

INDEX_ADVICE_SQL = """
SELECT *
FROM QSYS2.INDEX_ADVICE
ORDER BY ESTIMATED_TIME_SAVINGS DESC
FETCH FIRST ? ROWS ONLY
"""

TABLE_STATS_SQL = """
SELECT *
FROM QSYS2.SYSTABLESTAT
WHERE TABLE_SCHEMA = ?
ORDER BY ROWS DESC
FETCH FIRST ? ROWS ONLY
"""

INDEX_STATS_SQL = """
SELECT *
FROM QSYS2.SYSINDEXSTAT
WHERE TABLE_SCHEMA = ?
  AND TABLE_NAME = ?
ORDER BY LAST_USED_TIMESTAMP DESC
FETCH FIRST ? ROWS ONLY
"""

LOCK_WAITS_SQL = """
SELECT *
FROM QSYS2.LOCK_WAITS
ORDER BY WAIT_DURATION DESC
FETCH FIRST ? ROWS ONLY
"""

JOURNAL_INFO_SQL = """
SELECT *
FROM QSYS2.JOURNAL_INFO
ORDER BY JOURNAL_LIBRARY, JOURNAL_NAME
FETCH FIRST ? ROWS ONLY
"""

JOURNAL_RECEIVER_INFO_SQL = """
SELECT *
FROM QSYS2.JOURNAL_RECEIVER_INFO
ORDER BY JOURNAL_LIBRARY, JOURNAL_NAME, RECEIVER_ATTACH_TIMESTAMP DESC
FETCH FIRST ? ROWS ONLY
"""

SYSTABLES_IN_SCHEMA_SQL = """
SELECT TABLE_SCHEMA,
       TABLE_NAME,
       TABLE_TYPE,
       TABLE_TEXT,
       LAST_ALTERED_TIMESTAMP
FROM QSYS2.SYSTABLES
WHERE TABLE_SCHEMA = ?
ORDER BY TABLE_NAME
FETCH FIRST ? ROWS ONLY
"""

SYSCOLUMNS_FOR_TABLE_SQL = """
SELECT TABLE_SCHEMA,
       TABLE_NAME,
       COLUMN_NAME,
       DATA_TYPE,
       LENGTH,
       NUMERIC_SCALE,
       IS_NULLABLE,
       COLUMN_TEXT
FROM QSYS2.SYSCOLUMNS
WHERE TABLE_SCHEMA = ?
  AND TABLE_NAME = ?
ORDER BY ORDINAL_POSITION
FETCH FIRST ? ROWS ONLY
"""

SYSROUTINES_IN_SCHEMA_SQL = """
SELECT ROUTINE_SCHEMA,
       ROUTINE_NAME,
       ROUTINE_TYPE,
       SPECIFIC_NAME,
       CREATED,
       LAST_ALTERED,
       ROUTINE_DEFINITION
FROM QSYS2.SYSROUTINES
WHERE ROUTINE_SCHEMA = ?
ORDER BY ROUTINE_NAME
FETCH FIRST ? ROWS ONLY
"""

HTTP_GET_VERBOSE_SQL = "SELECT * FROM TABLE(QSYS2.HTTP_GET_VERBOSE(?)) X"
HTTP_POST_VERBOSE_SQL = "SELECT * FROM TABLE(QSYS2.HTTP_POST_VERBOSE(?, ?)) X"

# =============================================================================
# IBM i 7.6 NEW SERVICES SQL TEMPLATES
# =============================================================================

AUTHORITY_COLLECTION_IFS_SQL = """
SELECT *
FROM TABLE(QSYS2.AUTHORITY_COLLECTION_IFS())
WHERE PATH_NAME LIKE ?
ORDER BY PATH_NAME, AUTHORIZATION_NAME
FETCH FIRST ? ROWS ONLY
"""

VERIFY_NAME_SQL = """
SELECT *
FROM TABLE(QSYS2.VERIFY_NAME(?))
"""

SQLSTATE_INFO_SQL = """
SELECT *
FROM TABLE(QSYS2.SQLSTATE_INFO(?))
"""

DUMP_PLAN_CACHE_QRO_SQL = """
SELECT *
FROM TABLE(QSYS2.DUMP_PLAN_CACHE(QRO_HASH => ?))
"""

CERTIFICATE_USAGE_INFO_SQL = """
SELECT *
FROM TABLE(SYSTOOLS.CERTIFICATE_USAGE_INFO())
WHERE CERTIFICATE_STORE LIKE ?
FETCH FIRST ? ROWS ONLY
"""

USER_MFA_INFO_SQL = """
SELECT AUTHORIZATION_NAME,
       TOTP_AUTHENTICATION_LEVEL,
       TOTP_KEY_STATUS,
       TOTP_KEY_GENERATION_TIMESTAMP
FROM QSYS2.USER_INFO
WHERE (? = '*ALL' OR AUTHORIZATION_NAME = ?)
FETCH FIRST ? ROWS ONLY
"""

SUBSYSTEM_ROUTING_INFO_SQL = """
SELECT *
FROM QSYS2.SUBSYSTEM_ROUTING_INFO
WHERE (? IS NULL OR SUBSYSTEM_NAME = ?)
FETCH FIRST ? ROWS ONLY
"""

# =============================================================================
# PROGRAM SOURCE CODE ANALYSIS SQL TEMPLATES
# =============================================================================

PROGRAM_SOURCE_INFO_SQL = """
SELECT OBJLONGSCHEMA AS LIBRARY,
       OBJNAME AS PROGRAM,
       SOURCE_LIBRARY,
       SOURCE_FILE,
       SOURCE_MEMBER,
       OBJCREATED,
       TEXT_DESCRIPTION
FROM TABLE(QSYS2.OBJECT_STATISTICS(?, '*PGM *SRVPGM *MODULE'))
WHERE OBJNAME = ?
  AND SOURCE_FILE IS NOT NULL
FETCH FIRST ? ROWS ONLY
"""

SOURCE_MEMBER_INFO_SQL = """
SELECT SYSTEM_TABLE_SCHEMA,
       SYSTEM_TABLE_NAME,
       SYSTEM_TABLE_MEMBER,
       SOURCE_TYPE,
       NUMBER_ROWS,
       PARTITION_TEXT
FROM QSYS2.SYSMEMBERSTAT
WHERE SYSTEM_TABLE_SCHEMA = ?
  AND SYSTEM_TABLE_NAME = ?
  AND SYSTEM_TABLE_MEMBER = ?
"""

PROGRAM_REFERENCES_SQL = """
SELECT FROM_OBJECT_SCHEMA,
       FROM_OBJECT_NAME,
       TO_OBJECT_SCHEMA,
       TO_OBJECT_NAME,
       REFERENCE_TYPE
FROM QSYS2.PROGRAM_REFERENCES
WHERE FROM_OBJECT_SCHEMA = ?
  AND FROM_OBJECT_NAME = ?
FETCH FIRST ? ROWS ONLY
"""

LARGEST_OBJECTS_SQL = """
SELECT OBJLONGSCHEMA AS LIBRARY,
       OBJNAME AS OBJECT,
       OBJTYPE,
       OBJSIZE,
       LAST_USED_TIMESTAMP
FROM TABLE(QSYS2.OBJECT_STATISTICS(?, '*ALL')) X
ORDER BY OBJSIZE DESC
FETCH FIRST ? ROWS ONLY
"""

LIBRARY_SIZES_ALL_SQL = """
WITH libs (ln) AS (
  SELECT OBJNAME
  FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLSIMPLE', 'LIB')) AS L
)
SELECT
  ln AS LIBRARY,
  LI.OBJECT_COUNT,
  LI.LIBRARY_SIZE AS LIBRARY_SIZE_BYTES,
  ROUND(LI.LIBRARY_SIZE / 1e+9, 2) AS LIBRARY_SIZE_GB,
  LI.LIBRARY_SIZE_COMPLETE,
  LI.LIBRARY_TYPE,
  LI.TEXT_DESCRIPTION,
  LI.IASP_NAME,
  LI.IASP_NUMBER
FROM libs,
LATERAL (
  SELECT *
  FROM TABLE(
    QSYS2.LIBRARY_INFO(
      LIBRARY_NAME => ln,
      DETAILED_INFO => 'LIBRARY_SIZE'
    )
  )
) LI
ORDER BY LI.LIBRARY_SIZE DESC
FETCH FIRST ? ROWS ONLY
"""

LIBRARY_SIZES_EXCL_SYSTEM_SQL = """
WITH libs (ln) AS (
  SELECT OBJNAME
  FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLSIMPLE', 'LIB')) AS L
  WHERE LEFT(OBJNAME, 1) NOT IN ('Q', '#')
)
SELECT
  ln AS LIBRARY,
  LI.OBJECT_COUNT,
  LI.LIBRARY_SIZE AS LIBRARY_SIZE_BYTES,
  ROUND(LI.LIBRARY_SIZE / 1e+9, 2) AS LIBRARY_SIZE_GB,
  LI.LIBRARY_SIZE_COMPLETE,
  LI.LIBRARY_TYPE,
  LI.TEXT_DESCRIPTION,
  LI.IASP_NAME,
  LI.IASP_NUMBER
FROM libs,
LATERAL (
  SELECT *
  FROM TABLE(
    QSYS2.LIBRARY_INFO(
      LIBRARY_NAME => ln,
      DETAILED_INFO => 'LIBRARY_SIZE'
    )
  )
) LI
ORDER BY LI.LIBRARY_SIZE DESC
FETCH FIRST ? ROWS ONLY
"""

# =============================================================================
# GENERIC HELPERS (runbook/checklist templates + user query builder)
# =============================================================================

def _render_template(title: str, bullets: List[str]) -> str:
    lines = [f"# {title}", ""]
    for b in bullets:
        lines.append(f"- {b}")
    return "\n".join(lines)


def _build_user_table_query(schema: str, table: str, where_clause: str = "",
                           order_by: str = "", limit: int = 100) -> str:
    """
    Build a safe SELECT query for user tables.
    All identifiers must be validated before calling this.
    """
    base = f"SELECT * FROM {schema}.{table}"
    if where_clause:
        base += f" WHERE {where_clause}"
    if order_by:
        base += f" ORDER BY {order_by}"
    base += f" FETCH FIRST {limit} ROWS ONLY"
    return base


# =============================================================================
# TOOLS (Agent-callable) - ALL TOOLS IN ONE PLACE
# =============================================================================

# --- Ops / Observability ---
@tool(name="get-system-status", description="Retrieve overall IBM i system performance statistics using QSYS2.SYSTEM_STATUS.")
def get_system_status() -> str:
    return run_select(SYSTEM_STATUS_SQL)

@tool(name="get-system-activity", description="Retrieve current IBM i activity metrics using QSYS2.SYSTEM_ACTIVITY_INFO.")
def get_system_activity() -> str:
    return run_select(SYSTEM_ACTIVITY_SQL)

@tool(name="top-cpu-jobs", description="Show top CPU jobs using QSYS2.ACTIVE_JOB_INFO. Optional subsystem/user CSV filters.")
def top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    sbs = _safe_csv_idents(subsystem_csv, what="subsystem list") if subsystem_csv else ""
    usr = _safe_csv_idents(user_csv, what="user list") if user_csv else ""
    return run_select(TOP_CPU_JOBS_SQL, parameters=[sbs, usr, lim])

@tool(name="jobs-in-msgw", description="List jobs in MSGW status using QSYS2.ACTIVE_JOB_INFO.")
def jobs_in_msgw(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    return run_select(MSGW_JOBS_SQL, parameters=[lim])

@tool(name="qsysopr-messages", description="Fetch recent QSYSOPR messages using QSYS2.MESSAGE_QUEUE_INFO.")
def qsysopr_messages(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    return run_select(QSYSOPR_RECENT_MSGS_SQL, parameters=[lim])

@tool(name="netstat-snapshot", description="Snapshot of network connections using QSYS2.NETSTAT_INFO.")
def netstat_snapshot(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=1000)
    return run_select(NETSTAT_SUMMARY_SQL, parameters=[lim])

@tool(name="get-asp-info", description="Get ASP information from QSYS2.ASP_INFO.")
def get_asp_info() -> str:
    return run_select(ASP_INFO_SQL)

@tool(name="disk-hotspots", description="Show disks with highest percent used using QSYS2.SYSDISKSTAT.")
def disk_hotspots(limit: int = 10) -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    return run_select(DISK_HOTSPOTS_SQL, parameters=[lim])

@tool(name="output-queue-hotspots", description="Show output queues with the most spooled files using QSYS2.OUTPUT_QUEUE_INFO.")
def output_queue_hotspots(limit: int = 20) -> str:
    lim = _safe_limit(limit, default=20, max_n=500)
    return run_select(OUTQ_HOTSPOTS_SQL, parameters=[lim])

@tool(name="ended-jobs", description="Show recently ended jobs using SYSTOOLS.ENDED_JOB_INFO (if available).")
def ended_jobs(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    return run_select(ENDED_JOB_INFO_SQL, parameters=[lim])

@tool(name="job-queue-entries", description="Show job queue entries using SYSTOOLS.JOB_QUEUE_ENTRIES (if available).")
def job_queue_entries(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=2000)
    return run_select(JOB_QUEUE_ENTRIES_SQL, parameters=[lim])

@tool(name="user-storage-top", description="Show users consuming the most storage using QSYS2.USER_STORAGE.")
def user_storage_top(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    return run_select(USER_STORAGE_SQL, parameters=[lim])

@tool(name="ifs-largest-objects", description="List largest objects in an IFS path using QSYS2.IFS_OBJECT_STATISTICS(path).")
def ifs_largest_objects(path: str, limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=1000)
    if not path or not path.startswith("/"):
        raise ValueError("IFS path must start with '/'.")
    return run_select(IFS_OBJECT_STATISTICS_SQL, parameters=[path, lim])

@tool(name="objects-changed-recently", description="List objects changed in last N days using QSYS2.OBJECT_STATISTICS.")
def objects_changed_recently(days: int = 7, limit: int = 200) -> str:
    d = _safe_limit(days, default=7, max_n=3650)
    lim = _safe_limit(limit, default=200, max_n=2000)
    return run_select(OBJECT_CHANGED_RECENTLY_SQL, parameters=[d, lim])

# --- PTF / Inventory / Licensing ---
@tool(name="ptfs-requiring-ipl", description="List PTFs that require an IPL using QSYS2.PTF_INFO.")
def ptfs_requiring_ipl(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=2000)
    return run_select(PTF_IPL_REQUIRED_SQL, parameters=[lim])

@tool(name="software-products", description="List installed licensed products from QSYS2.SOFTWARE_PRODUCT_INFO. Optionally filter by product_id.")
def software_products(product_id: str = "", limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    pid = _safe_ident(product_id, what="product_id") if product_id else None
    return run_select(SOFTWARE_PRODUCT_INFO_SQL, parameters=[pid, pid, lim])

@tool(name="license-info", description="List license info using QSYS2.LICENSE_INFO.")
def license_info(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(LICENSE_INFO_SQL, parameters=[lim])

# --- Services discovery ---
@tool(name="search-sql-services", description="Search IBM i SQL services catalog (QSYS2.SERVICES_INFO) by name/category keyword.")
def search_sql_services(keyword: str, limit: int = 100) -> str:
    kw = (keyword or "").strip()
    if not kw:
        raise ValueError("keyword is required")
    lim = _safe_limit(limit, default=100, max_n=5000)
    like = f"%{kw}%"
    return run_select(SERVICES_SEARCH_SQL, parameters=[like, like, lim])

# --- Security ---
@tool(name="list-user-profiles", description="List IBM i user profiles (basic) using QSYS2.USER_INFO_BASIC.")
def list_user_profiles(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(USER_INFO_BASIC_SQL, parameters=[lim])

@tool(name="list-privileged-profiles", description="List user profiles with authorities/invalid signons using QSYS2.USER_INFO.")
def list_privileged_profiles(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(USER_INFO_PRIVILEGED_SQL, parameters=[lim])

@tool(name="public-all-object-authority", description="List objects where *PUBLIC has *ALL authority using QSYS2.OBJECT_PRIVILEGES.")
def public_all_object_authority(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(PUBLIC_ALL_OBJECTS_SQL, parameters=[lim])

@tool(name="object-privileges", description="Show privileges for a specific object (schema/object) using QSYS2.OBJECT_PRIVILEGES.")
def object_privileges(schema: str, object_name: str, limit: int = 2000) -> str:
    sch = _safe_schema(schema)
    obj = _safe_ident(object_name, what="object_name")
    lim = _safe_limit(limit, default=2000, max_n=20000)
    return run_select(OBJECT_PRIVILEGES_FOR_OBJECT_SQL, parameters=[sch, obj, lim])

@tool(name="authorization-lists", description="List authorization lists using QSYS2.AUTHORIZATION_LIST_INFO.")
def authorization_lists(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(AUTH_LIST_INFO_SQL, parameters=[lim])

@tool(name="authorization-list-entries", description="List entries in an authorization list using QSYS2.AUTHORIZATION_LIST_ENTRIES.")
def authorization_list_entries(auth_list_lib: str, auth_list_name: str, limit: int = 5000) -> str:
    lib = _safe_ident(auth_list_lib, what="auth_list_lib")
    name = _safe_ident(auth_list_name, what="auth_list_name")
    lim = _safe_limit(limit, default=5000, max_n=50000)
    return run_select(AUTH_LIST_ENTRIES_SQL, parameters=[lib, name, lim])

# --- SQL Performance ---
@tool(name="plan-cache-top", description="Top SQL statements by elapsed time using QSYS2.PLAN_CACHE_STATEMENT (if available).")
def plan_cache_top(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=5000)
    return run_select(PLAN_CACHE_TOP_SQL, parameters=[lim])

@tool(name="plan-cache-errors", description="SQL statements with errors/warnings using QSYS2.PLAN_CACHE_STATEMENT (if available).")
def plan_cache_errors(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=5000)
    return run_select(PLAN_CACHE_ERRORS_SQL, parameters=[lim])

@tool(name="index-advice", description="Index recommendations using QSYS2.INDEX_ADVICE (if available).")
def index_advice(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(INDEX_ADVICE_SQL, parameters=[lim])

@tool(name="schema-table-stats", description="List largest tables in a schema using QSYS2.SYSTABLESTAT.")
def schema_table_stats(schema: str, limit: int = 200) -> str:
    sch = _safe_schema(schema)
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(TABLE_STATS_SQL, parameters=[sch, lim])

@tool(name="table-index-stats", description="List index usage for a table using QSYS2.SYSINDEXSTAT.")
def table_index_stats(schema: str, table: str, limit: int = 500) -> str:
    sch = _safe_schema(schema)
    tbl = _safe_ident(table, what="table")
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(INDEX_STATS_SQL, parameters=[sch, tbl, lim])

@tool(name="lock-waits", description="Show lock waits/contenders using QSYS2.LOCK_WAITS (if available).")
def lock_waits(limit: int = 100) -> str:
    lim = _safe_limit(limit, default=100, max_n=5000)
    return run_select(LOCK_WAITS_SQL, parameters=[lim])

# --- HA/DR / Journaling ---
@tool(name="journals", description="List journals and configuration using QSYS2.JOURNAL_INFO.")
def journals(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(JOURNAL_INFO_SQL, parameters=[lim])

@tool(name="journal-receivers", description="List journal receivers using QSYS2.JOURNAL_RECEIVER_INFO.")
def journal_receivers(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(JOURNAL_RECEIVER_INFO_SQL, parameters=[lim])

# --- Integration (REST) ---
@tool(name="http-get-verbose", description="Call an HTTP GET using QSYS2.HTTP_GET_VERBOSE(url).")
def http_get_verbose(url: str) -> str:
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    return run_select(HTTP_GET_VERBOSE_SQL, parameters=[url])

@tool(name="http-post-verbose", description="Call an HTTP POST using QSYS2.HTTP_POST_VERBOSE(url, body).")
def http_post_verbose(url: str, body: str) -> str:
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    body = body or ""
    return run_select(HTTP_POST_VERBOSE_SQL, parameters=[url, body])

# --- Library / Object sizing ---
@tool(name="largest-objects", description="Find largest objects in a library using QSYS2.OBJECT_STATISTICS.")
def largest_objects(library: str, limit: int = 50) -> str:
    lib = _safe_ident_or_special(library, what="library")
    lim = _safe_limit(limit, default=50, max_n=5000)
    return run_select(LARGEST_OBJECTS_SQL, parameters=[lib, lim])

@tool(name="library-sizes", description="List libraries and their sizes using QSYS2.LIBRARY_INFO. Can exclude system libraries.")
def library_sizes(limit: int = 100, exclude_system: bool = False) -> str:
    lim = _safe_limit(limit, default=100, max_n=20000)
    sql = LIBRARY_SIZES_EXCL_SYSTEM_SQL if exclude_system else LIBRARY_SIZES_ALL_SQL
    return run_select(sql, parameters=[lim])

# --- Data Governance / Metadata ---
@tool(name="list-tables-in-schema", description="List tables/views in a schema using QSYS2.SYSTABLES.")
def list_tables_in_schema(schema: str, limit: int = 5000) -> str:
    sch = _safe_schema(schema)
    lim = _safe_limit(limit, default=5000, max_n=50000)
    return run_select(SYSTABLES_IN_SCHEMA_SQL, parameters=[sch, lim])

@tool(name="describe-table", description="Describe a table's columns using QSYS2.SYSCOLUMNS.")
def describe_table(schema: str, table: str, limit: int = 5000) -> str:
    sch = _safe_schema(schema)
    tbl = _safe_ident(table, what="table")
    lim = _safe_limit(limit, default=5000, max_n=50000)
    return run_select(SYSCOLUMNS_FOR_TABLE_SQL, parameters=[sch, tbl, lim])

@tool(name="list-routines-in-schema", description="List routines (procedures/functions) in a schema using QSYS2.SYSROUTINES.")
def list_routines_in_schema(schema: str, limit: int = 2000) -> str:
    sch = _safe_schema(schema)
    lim = _safe_limit(limit, default=2000, max_n=50000)
    return run_select(SYSROUTINES_IN_SCHEMA_SQL, parameters=[sch, lim])

# --- Logging (optional write tool) ---
@tool(name="log-performance-metrics", description="Save performance metrics to SAMPLE.METRICS for trend history (requires table).")
def log_performance_metrics(cpu_usage: float, asp_usage: float) -> str:
    sql = """
        INSERT INTO SAMPLE.METRICS (TS, CPU_PCT, ASP_PCT)
        VALUES (CURRENT_TIMESTAMP, ?, ?)
    """
    try:
        return run_sql_statement(sql, parameters=[cpu_usage, asp_usage])
    except Exception as e:
        return f"ERROR inserting metrics. Details: {type(e).__name__}: {e}"

# --- Runbook / Checklist tools ---
@tool(name="generate-runbook", description="Generate a runbook template for common IBM i scenarios (DR drill, switchover, incident response).")
def generate_runbook(runbook_type: str) -> str:
    t = (runbook_type or "").strip().lower()
    if t in {"dr", "disaster recovery", "recovery"}:
        return _render_template(
            "IBM i Disaster Recovery Runbook (Template)",
            [
                "Define scope: partitions, IASPs, apps, integrations",
                "RPO/RTO targets and success criteria",
                "Failover decision and approvals",
                "Backup validation + last good restore point",
                "Switchover steps + DNS/IP considerations",
                "Post-recovery validation (jobs, apps, interfaces)",
                "Audit log capture and incident report",
            ],
        )
    if t in {"switchover", "ha switchover", "failover"}:
        return _render_template(
            "IBM i HA Switchover Runbook (Template)",
            [
                "Pre-check: replication health + journal receiver lag",
                "Freeze non-essential batch and quiesce critical subsystems",
                "Execute planned switchover (PowerHA/replication steps)",
                "Validate Db2 and application connectivity",
                "Resume workloads and monitor for errors",
                "Document timings and update SOP",
            ],
        )
    return _render_template(
        f"Runbook Template: {runbook_type}",
        [
            "Objective and scope",
            "Pre-checks and prerequisites",
            "Step-by-step procedure",
            "Validation steps",
            "Rollback steps",
            "Post-incident documentation",
        ],
    )

@tool(name="generate-checklist", description="Generate checklists for releases, security posture, performance triage, or integration cutovers.")
def generate_checklist(checklist_type: str) -> str:
    t = (checklist_type or "").strip().lower()
    if t in {"release", "deployment", "devops"}:
        return _render_template(
            "IBM i Release/Deployment Checklist",
            [
                "Confirm change approval and maintenance window",
                "Compare PTF level and environment drift",
                "Validate object authority and ownership expectations",
                "Promote objects in correct dependency order",
                "Run smoke tests + critical business flows",
                "Monitor QSYSOPR + job logs for spikes",
                "Rollback plan ready and rehearsed",
            ],
        )
    if t in {"security", "compliance"}:
        return _render_template(
            "IBM i Security Posture Checklist",
            [
                "Review privileged profiles (*ALLOBJ/*SECADM etc.)",
                "Check *PUBLIC authorities on sensitive objects",
                "Confirm auditing is enabled for required event types",
                "Validate MFA coverage for admin profiles (if applicable)",
                "Review invalid sign-on attempts and lockouts",
                "Verify TLS configs and disallow insecure host servers",
            ],
        )
    if t in {"performance", "triage"}:
        return _render_template(
            "IBM i Performance Triage Checklist",
            [
                "Check system status (CPU, memory, disk/ASP)",
                "Identify top CPU jobs and their SQL statements",
                "Check MSGW jobs and QSYSOPR messages",
                "Inspect lock waits and contention hotspots",
                "Check disk hotspots and output queue backlogs",
                "Capture evidence and recommend next actions",
            ],
        )
    return _render_template(
        f"Checklist: {checklist_type}",
        ["Define objective", "Gather evidence", "Execute steps", "Validate outcome", "Document results"],
    )


# =============================================================================
# IBM i 7.6 SERVICES (NEW TOOLS)
# =============================================================================

@tool(name="ifs-authority-collection", description="Analyze IFS object authorities using QSYS2.AUTHORITY_COLLECTION_IFS (7.6/7.5 TR6+).")
def ifs_authority_collection(path_pattern: str = "%", limit: int = 200) -> str:
    """
    Returns authority collection data for IFS objects.
    path_pattern: IFS path pattern (supports %)
    """
    if not service_exists("QSYS2", "AUTHORITY_COLLECTION_IFS"):
        return "ERROR: AUTHORITY_COLLECTION_IFS not available. Requires IBM i 7.6 or 7.5 TR6+."

    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(AUTHORITY_COLLECTION_IFS_SQL, parameters=[path_pattern, lim])


@tool(name="verify-name", description="Validate system or SQL name using QSYS2.VERIFY_NAME (7.6/7.5 TR6+).")
def verify_name(name_to_check: str) -> str:
    """
    Checks if a name is valid as system object name or SQL name.
    """
    if not service_exists("QSYS2", "VERIFY_NAME"):
        return "ERROR: VERIFY_NAME not available. Requires IBM i 7.6 or 7.5 TR6+."

    return run_select(VERIFY_NAME_SQL, parameters=[name_to_check])


@tool(name="lookup-sqlstate", description="Get information about SQLSTATE values using QSYS2.SQLSTATE_INFO (7.6/7.5 TR6+).")
def lookup_sqlstate(sqlstate: str) -> str:
    """
    Returns detailed information about a specific SQLSTATE value.
    """
    if not service_exists("QSYS2", "SQLSTATE_INFO"):
        return "ERROR: SQLSTATE_INFO not available. Requires IBM i 7.6 or 7.5 TR6+."

    if len(sqlstate) != 5:
        raise ValueError("SQLSTATE must be exactly 5 characters")

    return run_select(SQLSTATE_INFO_SQL, parameters=[sqlstate])


@tool(name="dump-plan-cache-qro", description="Dump plan cache for specific QRO_HASH using enhanced QSYS2.DUMP_PLAN_CACHE (7.6).")
def dump_plan_cache_qro(qro_hash: int) -> str:
    """
    Enhanced DUMP_PLAN_CACHE with QRO_HASH filtering (7.6 only).
    qro_hash: 64-bit QRO hash value (BIGINT)
    """
    if not service_exists("QSYS2", "DUMP_PLAN_CACHE"):
        return "ERROR: DUMP_PLAN_CACHE not available."

    return run_select(DUMP_PLAN_CACHE_QRO_SQL, parameters=[qro_hash])


@tool(name="certificate-usage-info", description="Show digital certificate usage using SYSTOOLS.CERTIFICATE_USAGE_INFO (7.5 TR1+).")
def certificate_usage_info(store_pattern: str = "%", limit: int = 100) -> str:
    """
    Returns certificate usage information from certificate stores.
    """
    if not service_exists("SYSTOOLS", "CERTIFICATE_USAGE_INFO"):
        return "ERROR: CERTIFICATE_USAGE_INFO not available. Requires IBM i 7.5 TR1+."

    lim = _safe_limit(limit, default=100, max_n=5000)
    return run_select(CERTIFICATE_USAGE_INFO_SQL, parameters=[store_pattern, lim])


@tool(name="user-mfa-settings", description="Show MFA/TOTP settings for user profiles using QSYS2.USER_INFO (7.6/7.5 TR6+).")
def user_mfa_settings(user_profile: str = "*ALL", limit: int = 500) -> str:
    """
    Returns MFA authentication settings for user profiles.
    user_profile: Specific user or *ALL
    """
    lim = _safe_limit(limit, default=500, max_n=5000)

    if user_profile.upper() == "*ALL":
        return run_select(USER_MFA_INFO_SQL, parameters=["*ALL", "", lim])
    else:
        usr = _safe_ident(user_profile, what="user_profile")
        return run_select(USER_MFA_INFO_SQL, parameters=[usr, usr, lim])


@tool(name="subsystem-routing-info", description="Show subsystem routing entries using QSYS2.SUBSYSTEM_ROUTING_INFO (7.6).")
def subsystem_routing_info(subsystem: str = "", limit: int = 500) -> str:
    """
    Returns routing entries for subsystems.
    """
    if not service_exists("QSYS2", "SUBSYSTEM_ROUTING_INFO"):
        return "ERROR: SUBSYSTEM_ROUTING_INFO not available. Requires IBM i 7.6."

    lim = _safe_limit(limit, default=500, max_n=5000)

    if subsystem:
        sbs = _safe_ident(subsystem, what="subsystem")
        return run_select(SUBSYSTEM_ROUTING_INFO_SQL, parameters=[sbs, sbs, lim])
    else:
        return run_select(SUBSYSTEM_ROUTING_INFO_SQL, parameters=[None, None, lim])


# =============================================================================
# PROGRAM SOURCE CODE ANALYSIS (NEW TOOLS)
# =============================================================================

@tool(name="get-program-source-info", description="Get source file location for a program using QSYS2.OBJECT_STATISTICS.")
def get_program_source_info(library: str, program: str, limit: int = 10) -> str:
    """
    Returns source file metadata (library, file, member) for a program.
    Works for *PGM, *SRVPGM, *MODULE objects.

    Use library='*ALL' to search all libraries, or specify a library name.
    """
    lib = _safe_ident_or_special(library, what="library")
    pgm = _safe_ident(program, what="program")
    lim = _safe_limit(limit, default=10, max_n=100)

    return run_select(PROGRAM_SOURCE_INFO_SQL, parameters=[lib, pgm, lim])


@tool(name="read-source-member", description="Read source code from a source physical file member.")
def read_source_member(library: str, source_file: str, member: str, limit: int = 1000) -> str:
    """
    Reads actual source code lines from a source physical file member.
    Returns up to 'limit' lines of source code.

    SAFETY: This respects schema whitelist - source file must be in allowed schema.
    """
    lib = _safe_schema(library)  # Validates against whitelist
    srcf = _safe_ident(source_file, what="source_file")
    mbr = _safe_ident(member, what="member")
    lim = _safe_limit(limit, default=1000, max_n=10000)

    # Log if reading from user schema
    if lib in _USER_SCHEMAS:
        print(f"[USER_SCHEMA_ACCESS] Reading source: {lib}/{srcf}({mbr})", file=sys.stderr)

    try:
        # Get member metadata
        metadata = run_select(SOURCE_MEMBER_INFO_SQL, parameters=[lib, srcf, mbr])

        # Read source lines
        sql = f"SELECT SRCSEQ, SRCDAT, SRCDTA FROM {lib}.{srcf} ORDER BY SRCSEQ FETCH FIRST {lim} ROWS ONLY"
        source = run_select(sql)

        return f"=== Member Metadata ===\n{metadata}\n\n=== Source Code ===\n{source}"
    except Exception as e:
        return f"ERROR reading source member. Details: {type(e).__name__}: {e}"


@tool(name="analyze-program-dependencies", description="Show what objects a program references using QSYS2.PROGRAM_REFERENCES.")
def analyze_program_dependencies(library: str, program: str, limit: int = 500) -> str:
    """
    Returns list of objects referenced by a program (calls, file usage, etc.).
    """
    if not service_exists("QSYS2", "PROGRAM_REFERENCES"):
        return "ERROR: PROGRAM_REFERENCES not available. May require IBM i 7.4+ or PTF."

    lib = _safe_ident(library, what="library")
    pgm = _safe_ident(program, what="program")
    lim = _safe_limit(limit, default=500, max_n=5000)

    return run_select(PROGRAM_REFERENCES_SQL, parameters=[lib, pgm, lim])


# =============================================================================
# USER SCHEMA / BUSINESS DATA ACCESS (NEW TOOLS)
# =============================================================================

@tool(name="query-user-table", description="Query business data from user-defined tables (requires ALLOWED_USER_SCHEMAS).")
def query_user_table(schema: str, table: str, where_clause: str = "",
                     order_by: str = "", limit: int = 100) -> str:
    """
    Flexible query tool for user business data.

    Examples:
    - "top 3 orders from yesterday":
      schema=ORDERLIB, where_clause="ORDER_DATE >= CURRENT_DATE - 1 DAY",
      order_by="ORDER_TOTAL DESC", limit=3

    - "customers by revenue":
      schema=CUSTLIB, table=CUSTOMERS, order_by="TOTAL_REVENUE DESC", limit=100

    SAFETY: Only works if schema is in ALLOWED_USER_SCHEMAS environment variable.
    """
    try:
        sch = _safe_schema(schema)
        tbl = _safe_ident(table, what="table")
        lim = _safe_limit(limit, default=100, max_n=5000)

        # Verify schema is in whitelist
        if sch not in _ALLOWED_SCHEMAS:
            return f"ERROR: Schema {sch} is not in allowed schemas. " \
                   f"System schemas: {sorted(_SYSTEM_SCHEMAS)}. " \
                   f"User schemas: {sorted(_USER_SCHEMAS)}. " \
                   f"To enable: Set ALLOWED_USER_SCHEMAS={sch} in .env"

        # Validate WHERE and ORDER BY don't contain dangerous tokens
        if where_clause:
            if _FORBIDDEN_SQL_TOKENS.search(where_clause):
                return "ERROR: Forbidden SQL operation in WHERE clause"

        if order_by:
            # Basic validation - should only be column names and ASC/DESC
            if _FORBIDDEN_SQL_TOKENS.search(order_by) or "(" in order_by:
                return "ERROR: Forbidden SQL operation in ORDER BY clause"

        # Log user schema access
        if sch in _USER_SCHEMAS:
            print(f"[USER_SCHEMA_ACCESS] Query: {sch}.{tbl}, WHERE={where_clause}, ORDER BY={order_by}, LIMIT={lim}",
                  file=sys.stderr)

        # Build dynamic query
        sql = _build_user_table_query(sch, tbl, where_clause, order_by, lim)

        return run_select(sql)
    except ValueError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@tool(name="describe-user-table", description="Describe columns of a user table using QSYS2.SYSCOLUMNS.")
def describe_user_table(schema: str, table: str) -> str:
    """
    Returns column metadata for a user table.
    Same as describe-table but with explicit user-schema logging.
    """
    sch = _safe_schema(schema)
    tbl = _safe_ident(table, what="table")

    if sch not in _ALLOWED_SCHEMAS:
        return f"ERROR: Schema {sch} is not in allowed schemas."

    if sch in _USER_SCHEMAS:
        print(f"[USER_SCHEMA_ACCESS] Describe table: {sch}.{tbl}", file=sys.stderr)

    return run_select(SYSCOLUMNS_FOR_TABLE_SQL, parameters=[sch, tbl, 5000])


@tool(name="count-user-table-rows", description="Count rows in a user table (fast metadata query).")
def count_user_table_rows(schema: str, table: str) -> str:
    """
    Returns row count for a table using metadata.
    Fast operation that doesn't scan the table.
    """
    sch = _safe_schema(schema)
    tbl = _safe_ident(table, what="table")

    if sch not in _ALLOWED_SCHEMAS:
        return f"ERROR: Schema {sch} is not in allowed schemas."

    if sch in _USER_SCHEMAS:
        print(f"[USER_SCHEMA_ACCESS] Count rows: {sch}.{tbl}", file=sys.stderr)

    sql = "SELECT NUMBER_ROWS, NUMBER_DELETED_ROWS, DATA_SIZE FROM QSYS2.SYSTABLESTAT WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?"
    return run_select(sql, parameters=[sch, tbl])


# =============================================================================
# SINGLE SUPER AGENT
# =============================================================================

def build_super_agent() -> Agent:
    model_id = os.getenv("OPENROUTER_MODEL_ID", "google/gemini-3-flash-preview")

    all_tools = [
        # Ops / Observability
        get_system_status, get_system_activity, top_cpu_jobs, jobs_in_msgw, qsysopr_messages,
        netstat_snapshot, get_asp_info, disk_hotspots, output_queue_hotspots,
        ended_jobs, job_queue_entries, user_storage_top, ifs_largest_objects,
        objects_changed_recently,

        # PTF / inventory / licensing
        ptfs_requiring_ipl, software_products, license_info,

        # Services discovery
        search_sql_services,

        # Security
        list_user_profiles, list_privileged_profiles, public_all_object_authority,
        object_privileges, authorization_lists, authorization_list_entries,

        # SQL Performance
        plan_cache_top, plan_cache_errors, index_advice,
        schema_table_stats, table_index_stats, lock_waits,

        # HA/DR / Journaling
        journals, journal_receivers,

        # Integration
        http_get_verbose, http_post_verbose,

        # Library sizing
        largest_objects, library_sizes,

        # Metadata
        list_tables_in_schema, describe_table, list_routines_in_schema,

        # Optional write logging
        log_performance_metrics,

        # Templates
        generate_runbook, generate_checklist,

        # IBM i 7.6 Services (NEW)
        ifs_authority_collection, verify_name, lookup_sqlstate,
        dump_plan_cache_qro, certificate_usage_info, user_mfa_settings,
        subsystem_routing_info,

        # Program Source Analysis (NEW)
        get_program_source_info, read_source_member,
        analyze_program_dependencies,

        # User Data Access (NEW)
        query_user_table, describe_user_table, count_user_table_rows,
    ]

    return Agent(
        name="IBM i Super Assistant (7.6 Edition)",
        model=OpenRouter(id=model_id),
        tools=all_tools,
        instructions=dedent("""
        You are an expert IBM i Super Assistant (IBM i 7.6 Edition).

        Core rules:
        - Use ONLY the provided tools to fetch IBM i system data.
        - Do NOT ask the user to run SQL manually.
        - For system data questions, call tools and cite results as evidence.
        - If a tool returns an ERROR (missing service, permissions, etc.):
          explain it clearly and propose alternatives (e.g., search-sql-services).

        IBM i 7.6 Enhancements:
        - NEW: IFS authority analysis (ifs-authority-collection)
        - NEW: Name validation (verify-name)
        - NEW: SQLSTATE lookup (lookup-sqlstate)
        - NEW: Enhanced plan cache (dump-plan-cache-qro)
        - NEW: Certificate tracking (certificate-usage-info)
        - NEW: MFA settings (user-mfa-settings)
        - NEW: Subsystem routing (subsystem-routing-info)

        User Schema Access (Business Data):
        - If ALLOWED_USER_SCHEMAS is configured, you can query user business data
        - Use: query-user-table, describe-user-table, count-user-table-rows
        - Examples: "top 3 orders from yesterday", "customers by revenue"
        - All user schema queries are logged for audit purposes

        Program Source Code:
        - Use get-program-source-info to find where source code lives
        - Use read-source-member to read actual source code
        - Use analyze-program-dependencies to see what a program calls

        Default mode:
        - Read-only analysis and recommendations.
        - Provide operationally safe guidance (plans/checklists/runbooks), not destructive execution.

        How to choose tools (examples):
        - Performance/CPU slowness: get-system-status, get-system-activity, top-cpu-jobs, lock-waits, plan-cache-top, dump-plan-cache-qro
        - Jobs stuck/hangs: jobs-in-msgw, qsysopr-messages, ended-jobs
        - Disk growth/space: get-asp-info, disk-hotspots, output-queue-hotspots, library-sizes, largest-objects, ifs-largest-objects
        - PTF/IPL readiness: ptfs-requiring-ipl, software-products, license-info
        - Security posture: list-privileged-profiles, public-all-object-authority, object-privileges, authorization-lists, user-mfa-settings
        - Db2 SQL tuning: plan-cache-top, plan-cache-errors, index-advice, schema-table-stats, table-index-stats
        - Journaling/HA/DR: journals, journal-receivers, generate-runbook
        - REST integration: http-get-verbose, http-post-verbose
        - Metadata discovery: list-tables-in-schema, describe-table, list-routines-in-schema
        - IFS security: ifs-authority-collection
        - Program analysis: get-program-source-info, read-source-member, analyze-program-dependencies
        - Business data: query-user-table, describe-user-table, count-user-table-rows
        - Name validation: verify-name
        - Error diagnosis: lookup-sqlstate

        Output format (always):
        - Summary
        - Evidence (tool outputs)
        - Interpretation
        - Next Actions (safe, ordered steps)
        """).strip(),
        markdown=True,
    )


# =============================================================================
# MAIN LOOP
# =============================================================================

def main() -> None:
    _ = get_ibmi_credentials()
    _ = _require_env("OPENROUTER_API_KEY")

    agent = build_super_agent()

    print("\n✅ IBM i Super Agent is ready (IBM i 7.6 Edition - 55 tools).")
    print("Try questions like:")
    print(" - 'What are the top CPU jobs right now?'")
    print(" - 'Any jobs stuck in MSGW? Show details.'")
    print(" - 'Show ASP info and disk hotspots.'")
    print(" - 'Any PTFs requiring IPL?'")
    print(" - 'List objects where *PUBLIC has *ALL authority.'")
    print(" - 'Show plan cache top SQL and index advice.'")
    print(" - 'Generate a DR runbook.'")
    print(" - 'List tables in schema MYLIB and describe table X.'")
    print("\nIBM i 7.6 NEW:")
    print(" - 'Show IFS authority for /home/myuser'")
    print(" - 'What are the MFA settings for users?'")
    print(" - 'Verify the name MYLIB123 is valid'")
    print(" - 'Look up SQLSTATE 42501'")
    print(" - 'Get source info for MYLIB.MYPGM'")
    print(" - 'Read source from QGPL/QRPGLESRC member MYPGM'")
    print(" - 'Query top 10 from PRODDATA.ORDERS by ORDER_DATE DESC'")
    print("\nType a question (or 'exit' to quit).\n")

    while True:
        user_q = input("You> ").strip()
        if user_q.lower() in {"exit", "quit"}:
            break
        if not user_q:
            continue

        # print_response is fine for CLI usage
        agent.print_response(user_q)


if __name__ == "__main__":
    main()
