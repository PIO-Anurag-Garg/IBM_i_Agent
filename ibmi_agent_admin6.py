
import os
import re
import json
from textwrap import dedent
from typing import Any, Dict, Optional, List, Callable, Tuple

from dotenv import load_dotenv
from mapepire_python import connect
from pep249 import QueryParameters

from agno.agent import Agent
from agno.models.anthropic import Claude
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
    """
    Mapepire cursor fetch APIs typically return a dict-like structure.
    We try to present a readable JSON string for the agent to interpret.
    """
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


# =============================================================================
# SAFETY HELPERS (Prevent SQL injection; allow only safe identifiers & SELECT tools)
# =============================================================================

_SAFE_IDENT = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)
_SAFE_SCHEMA = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)
_FORBIDDEN_SQL_TOKENS = re.compile(
    r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bMERGE\b|\bDROP\b|\bALTER\b|\bCREATE\b|\bCALL\b|\bGRANT\b|\bREVOKE\b|\bRUN\b|\bCL:\b|\bQCMDEXC\b)",
    re.IGNORECASE,
)

# Allow queries against known system schemas (safe and expected for IBM i Services & catalogs)
_ALLOWED_SCHEMAS = {"QSYS2", "SYSTOOLS", "SYSIBM", "QSYS", "INFORMATION_SCHEMA"}


def _safe_ident(value: str, what: str = "identifier") -> str:
    """Validate an IBM i-ish identifier (library, object, user, subsystem, etc.)."""
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()


def _safe_schema(value: str) -> str:
    v = (value or "").strip()
    if not v or not _SAFE_SCHEMA.match(v):
        raise ValueError(f"Invalid schema: {value!r}")
    return v.upper()


def _safe_csv_idents(value: str, what: str = "list") -> str:
    """Validate comma-separated identifiers; returns normalized CSV in upper-case with no spaces."""
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

    # Best-effort schema check (heuristic)
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
    _looks_like_safe_select(sql)
    try:
        return run_sql_statement(sql, parameters=parameters)
    except Exception as e:
        return f"ERROR executing SQL Service/cat query. Details: {type(e).__name__}: {e}"


# =============================================================================
# SQL TEMPLATES (IBM i Services + Catalogs)
# =============================================================================

SYSTEM_STATUS_SQL = (
    "SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS(RESET_STATISTICS => 'NO', DETAILED_INFO => 'ALL')) X"
)
SYSTEM_ACTIVITY_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_ACTIVITY_INFO())"

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

SERVICES_SEARCH_SQL = """
SELECT SERVICE_CATEGORY,
       SERVICE_SCHEMA_NAME,
       SERVICE_NAME,
       SQL_OBJECT_TYPE,
       EARLIEST_POSSIBLE_RELEASE
FROM QSYS2.SERVICES_INFO
WHERE (UPPER(SERVICE_NAME) LIKE UPPER(?) OR UPPER(SERVICE_CATEGORY) LIKE UPPER(?))
ORDER BY SERVICE_CATEGORY, SERVICE_SCHEMA_NAME, SERVICE_NAME
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

HTTP_GET_VERBOSE_SQL = """
SELECT *
FROM TABLE(QSYS2.HTTP_GET_VERBOSE(?)) X
"""

HTTP_POST_VERBOSE_SQL = """
SELECT *
FROM TABLE(QSYS2.HTTP_POST_VERBOSE(?, ?)) X
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
# GENERIC "TEMPLATE/PLAYBOOK" HELPERS
# =============================================================================

def _render_template(title: str, bullets: List[str]) -> str:
    lines = [f"# {title}", ""]
    for b in bullets:
        lines.append(f"- {b}")
    return "\n".join(lines)


# =============================================================================
# TOOLS (Agent-callable)
# =============================================================================

@tool(name="get-system-status", description="Retrieve overall IBM i system performance statistics using QSYS2.SYSTEM_STATUS.")
def get_system_status() -> str:
    return run_select(SYSTEM_STATUS_SQL)

@tool(name="get-system-activity", description="Retrieve current IBM i activity metrics using QSYS2.SYSTEM_ACTIVITY_INFO.")
def get_system_activity() -> str:
    return run_select(SYSTEM_ACTIVITY_SQL)

@tool(name="top-cpu-jobs", description="Show top CPU consuming jobs using QSYS2.ACTIVE_JOB_INFO. Optional subsystem/user CSV filters.")
def top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    sbs = _safe_csv_idents(subsystem_csv, what="subsystem list") if subsystem_csv else ""
    usr = _safe_csv_idents(user_csv, what="user list") if user_csv else ""
    return run_select(TOP_CPU_JOBS_SQL, parameters=[sbs, usr, lim])

@tool(name="jobs-in-msgw", description="List jobs in MSGW (message wait) status using QSYS2.ACTIVE_JOB_INFO.")
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

@tool(name="ptfs-requiring-ipl", description="List PTFs that require an IPL using QSYS2.PTF_INFO.")
def ptfs_requiring_ipl(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=2000)
    return run_select(PTF_IPL_REQUIRED_SQL, parameters=[lim])

@tool(name="software-products", description="List licensed products from QSYS2.SOFTWARE_PRODUCT_INFO. Optionally filter by product_id.")
def software_products(product_id: str = "", limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    pid = _safe_ident(product_id, what="product_id") if product_id else None
    return run_select(SOFTWARE_PRODUCT_INFO_SQL, parameters=[pid, pid, lim])

@tool(name="license-info", description="List license info using QSYS2.LICENSE_INFO.")
def license_info(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(LICENSE_INFO_SQL, parameters=[lim])

@tool(name="search-sql-services", description="Search IBM i SQL services catalog (QSYS2.SERVICES_INFO) by name/category keyword.")
def search_sql_services(keyword: str, limit: int = 100) -> str:
    kw = (keyword or "").strip()
    if not kw:
        raise ValueError("keyword is required")
    lim = _safe_limit(limit, default=100, max_n=5000)
    like = f"%{kw}%"
    return run_select(SERVICES_SEARCH_SQL, parameters=[like, like, lim])

@tool(name="list-user-profiles", description="List IBM i user profiles using QSYS2.USER_INFO_BASIC.")
def list_user_profiles(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(USER_INFO_BASIC_SQL, parameters=[lim])

@tool(name="list-privileged-profiles", description="List privileged user profiles using QSYS2.USER_INFO.")
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

@tool(name="lock-waits", description="Show lock waits using QSYS2.LOCK_WAITS (if available).")
def lock_waits(limit: int = 100) -> str:
    lim = _safe_limit(limit, default=100, max_n=5000)
    return run_select(LOCK_WAITS_SQL, parameters=[lim])

@tool(name="journals", description="List journals using QSYS2.JOURNAL_INFO.")
def journals(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(JOURNAL_INFO_SQL, parameters=[lim])

@tool(name="journal-receivers", description="List journal receivers using QSYS2.JOURNAL_RECEIVER_INFO.")
def journal_receivers(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(JOURNAL_RECEIVER_INFO_SQL, parameters=[lim])

@tool(name="http-get-verbose", description="Call HTTP GET using QSYS2.HTTP_GET_VERBOSE(url).")
def http_get_verbose(url: str) -> str:
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    return run_select(HTTP_GET_VERBOSE_SQL, parameters=[url])

@tool(name="http-post-verbose", description="Call HTTP POST using QSYS2.HTTP_POST_VERBOSE(url, body).")
def http_post_verbose(url: str, body: str) -> str:
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("url must start with http:// or https://")
    body = body or ""
    return run_select(HTTP_POST_VERBOSE_SQL, parameters=[url, body])

@tool(name="largest-objects", description="Find largest objects in a library using QSYS2.OBJECT_STATISTICS.")
def largest_objects(library: str, limit: int = 50) -> str:
    lib = _safe_ident(library, what="library")
    lim = _safe_limit(limit, default=50, max_n=5000)
    return run_select(LARGEST_OBJECTS_SQL, parameters=[lib, lim])

@tool(name="library-sizes", description="List libraries and their sizes using QSYS2.LIBRARY_INFO.")
def library_sizes(limit: int = 100, exclude_system: bool = False) -> str:
    lim = _safe_limit(limit, default=100, max_n=20000)
    sql = LIBRARY_SIZES_EXCL_SYSTEM_SQL if exclude_system else LIBRARY_SIZES_ALL_SQL
    return run_select(sql, parameters=[lim])

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

@tool(name="list-routines-in-schema", description="List routines in a schema using QSYS2.SYSROUTINES.")
def list_routines_in_schema(schema: str, limit: int = 2000) -> str:
    sch = _safe_schema(schema)
    lim = _safe_limit(limit, default=2000, max_n=50000)
    return run_select(SYSROUTINES_IN_SCHEMA_SQL, parameters=[sch, lim])

@tool(name="log-performance-metrics", description="Save metrics to SAMPLE.METRICS (requires table).")
def log_performance_metrics(cpu_usage: float, asp_usage: float) -> str:
    sql = """
        INSERT INTO SAMPLE.METRICS (TS, CPU_PCT, ASP_PCT)
        VALUES (CURRENT_TIMESTAMP, ?, ?)
    """
    try:
        return run_sql_statement(sql, parameters=[cpu_usage, asp_usage])
    except Exception as e:
        return f"ERROR inserting metrics. Details: {type(e).__name__}: {e}"

@tool(name="generate-runbook", description="Generate a runbook template for common IBM i scenarios.")
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

@tool(name="generate-checklist", description="Generate checklists for releases, security, performance triage, integration cutovers.")
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
# MULTI-AGENT BUILDERS
# =============================================================================

def _model() -> Claude:
    model_id = os.getenv("CLAUDE_MODEL_ID", "claude-sonnet-4-5-20250929")
    return Claude(id=model_id)

def _base_instructions(agent_name: str, focus: str) -> str:
    return dedent(
        f"""
        You are {agent_name}, an expert IBM i specialist agent.

        Focus:
        {focus}

        Tooling rules:
        - Use ONLY the provided tools for IBM i data retrieval or external calls.
        - Use service discovery tool 'search-sql-services' when needed.

        Output format:
        - Use Markdown.
        - Provide: Summary, Evidence (tool results), Interpretation, Next actions.
        - Never invent system data; if you can't retrieve it, say so clearly.

        Safety & governance:
        - Default to read-only analysis.
        - For destructive/privileged steps, produce a plan/checklist, not execution.
        """
    ).strip()

def build_ops_agent() -> Agent:
    return Agent(
        name="Ops & Observability Agent",
        model=_model(),
        tools=[
            get_system_status, get_system_activity, top_cpu_jobs, jobs_in_msgw,
            qsysopr_messages, netstat_snapshot, get_asp_info, disk_hotspots,
            output_queue_hotspots, ended_jobs, job_queue_entries, user_storage_top,
            ifs_largest_objects, objects_changed_recently, search_sql_services,
            generate_checklist,
        ],
        instructions=_base_instructions(
            "Ops & Observability Agent",
            "System health, jobs/subsystems, messages, performance triage, operational summaries."
        ),
        markdown=True,
    )

def build_security_agent() -> Agent:
    return Agent(
        name="Security & Compliance Agent",
        model=_model(),
        tools=[
            list_user_profiles, list_privileged_profiles, public_all_object_authority,
            object_privileges, authorization_lists, authorization_list_entries,
            qsysopr_messages, search_sql_services, generate_checklist,
        ],
        instructions=_base_instructions(
            "Security & Compliance Agent",
            "IBM i security posture, profiles/authorities, audit evidence prep, and compliance summaries."
        ),
        markdown=True,
    )

def build_sql_perf_agent() -> Agent:
    return Agent(
        name="Db2 SQL Performance Agent",
        model=_model(),
        tools=[
            plan_cache_top, plan_cache_errors, index_advice, schema_table_stats,
            table_index_stats, lock_waits, search_sql_services, generate_checklist,
        ],
        instructions=_base_instructions(
            "Db2 SQL Performance Agent",
            "Slow SQL diagnosis, index suggestions, plan cache insights, locking hotspots, tuning actions."
        ),
        markdown=True,
    )

def build_code_modernization_agent() -> Agent:
    return Agent(
        name="RPG/CL Modernization Agent",
        model=_model(),
        tools=[search_sql_services, generate_checklist],
        instructions=_base_instructions(
            "RPG/CL Modernization Agent",
            "Modernization guidance, refactoring strategies, documentation patterns, and safe migration plans."
        ) + "\n\nNote: This script does not access source members; provide modernization guidance and checklists.",
        markdown=True,
    )

def build_devops_agent() -> Agent:
    return Agent(
        name="DevOps & Release Agent",
        model=_model(),
        tools=[
            ptfs_requiring_ipl, software_products, license_info,
            objects_changed_recently, search_sql_services, generate_checklist,
        ],
        instructions=_base_instructions(
            "DevOps & Release Agent",
            "Release readiness, PTF/IPL planning, drift evidence, rollback planning, deployment checklists."
        ),
        markdown=True,
    )

def build_integration_agent() -> Agent:
    return Agent(
        name="Integration & API Agent",
        model=_model(),
        tools=[http_get_verbose, http_post_verbose, search_sql_services, generate_checklist],
        instructions=_base_instructions(
            "Integration & API Agent",
            "REST integration from IBM i, TLS/cert troubleshooting guidance, monitoring plans, migration to REST."
        ),
        markdown=True,
    )

def build_streaming_agent() -> Agent:
    return Agent(
        name="Event Streaming / CDC Agent",
        model=_model(),
        tools=[journals, journal_receivers, search_sql_services, generate_runbook, generate_checklist],
        instructions=_base_instructions(
            "Event Streaming / CDC Agent",
            "Journaling-based CDC planning, event schema design, streaming architecture guidance, replay strategies."
        ) + "\n\nNote: This script does not execute Kafka operations; provide designs + validate journaling via tools.",
        markdown=True,
    )

def build_hadr_agent() -> Agent:
    return Agent(
        name="HA/DR & Cyber Resilience Agent",
        model=_model(),
        tools=[
            journals, journal_receivers, ptfs_requiring_ipl,
            library_sizes, largest_objects, ifs_largest_objects,
            search_sql_services, generate_runbook, generate_checklist,
        ],
        instructions=_base_instructions(
            "HA/DR & Cyber Resilience Agent",
            "HA/DR posture, journaling health, backup readiness, resilience planning, runbooks."
        ),
        markdown=True,
    )

def build_capacity_agent() -> Agent:
    return Agent(
        name="Capacity & Cost Optimization Agent",
        model=_model(),
        tools=[
            get_system_status, get_system_activity, top_cpu_jobs,
            get_asp_info, disk_hotspots, user_storage_top,
            library_sizes, largest_objects, ifs_largest_objects,
            search_sql_services, generate_checklist,
        ],
        instructions=_base_instructions(
            "Capacity & Cost Optimization Agent",
            "Forecasting resource usage patterns, identifying growth drivers, capacity planning actions."
        ),
        markdown=True,
    )

def build_ai_strategy_agent() -> Agent:
    return Agent(
        name="AI Enablement & Platform Strategy Agent",
        model=_model(),
        tools=[search_sql_services, generate_checklist, generate_runbook],
        instructions=_base_instructions(
            "AI Enablement & Platform Strategy Agent",
            "AI agent platform strategy, guardrails, hybrid vs on-platform decisioning, pilot planning."
        ),
        markdown=True,
    )

def build_data_governance_agent() -> Agent:
    return Agent(
        name="Data Governance & Discovery Agent",
        model=_model(),
        tools=[
            list_tables_in_schema, describe_table, list_routines_in_schema,
            object_privileges, library_sizes, largest_objects,
            search_sql_services, generate_checklist,
        ],
        instructions=_base_instructions(
            "Data Governance & Discovery Agent",
            "Metadata discovery, schema documentation, data dictionary drafts, lineage/dependency guidance."
        ),
        markdown=True,
    )

def build_helpdesk_agent() -> Agent:
    return Agent(
        name="IBM i Helpdesk Agent",
        model=_model(),
        tools=[
            qsysopr_messages, jobs_in_msgw, ended_jobs, top_cpu_jobs,
            list_privileged_profiles, public_all_object_authority,
            ptfs_requiring_ipl, search_sql_services, generate_checklist,
        ],
        instructions=_base_instructions(
            "IBM i Helpdesk Agent",
            "First-line triage, explaining errors/messages, evidence gathering, ticket-ready summaries."
        ),
        markdown=True,
    )

# =============================================================================
# ORCHESTRATOR / MODEL-BASED ROUTER
# =============================================================================

AGENT_BUILDERS: Dict[str, Callable[[], Agent]] = {
    "ops": build_ops_agent,
    "security": build_security_agent,
    "sqlperf": build_sql_perf_agent,
    "modernize": build_code_modernization_agent,
    "devops": build_devops_agent,
    "integration": build_integration_agent,
    "streaming": build_streaming_agent,
    "hadr": build_hadr_agent,
    "capacity": build_capacity_agent,
    "aistrategy": build_ai_strategy_agent,
    "datagov": build_data_governance_agent,
    "helpdesk": build_helpdesk_agent,
}

_ALLOWED_AGENT_KEYS = set(AGENT_BUILDERS.keys())

def build_all_agents() -> Dict[str, Agent]:
    return {k: v() for k, v in AGENT_BUILDERS.items()}

def build_router_agent() -> Agent:
    """
    LLM-based router. Must return STRICT JSON only.
    We use Agent.run() to capture the JSON reliably. [1](https://ibmuser.com/train/dsfolder/ase1ds.htm)[2](https://developer.ibm.com/tutorials/awb-using-ibm-granite-llms-in-watsonx-ai-flows-engine)
    """
    return Agent(
        name="IBM i Router (LLM)",
        model=_model(),
        tools=[],
        markdown=False,
        instructions=dedent(f"""
        You are a strict routing classifier for an IBM i multi-agent assistant.

        Return ONLY valid JSON (no markdown, no prose) with this schema:
        {{
          "agent": "<one of: {", ".join(sorted(_ALLOWED_AGENT_KEYS))}>",
          "confidence": <float 0.0-1.0>,
          "reason": "<short reason>",
          "secondary_agents": ["<agent>", ...]  // optional, max 2
        }}

        Rules:
        - Pick "helpdesk" if uncertain.
        - If the user question is multi-intent, choose the best primary agent and up to 2 secondary agents.
        - Never include agents not in the allowed list.
        - Be consistent and conservative: prefer helpdesk if ambiguous.
        """).strip(),
    )

def _extract_json_object(text: str) -> Optional[str]:
    """
    Robustly extract first JSON object from a string.
    Handles cases where model accidentally adds extra text.
    """
    if not text:
        return None
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    # Try to find first {...} block
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    return m.group(0).strip() if m else None

def route_question_llm(user_q: str, router_agent: Agent) -> Dict[str, Any]:
    """
    Returns dict: {agent, confidence, reason, secondary_agents}
    Uses Agent.run() (not print_response) to get the router output reliably. [1](https://ibmuser.com/train/dsfolder/ase1ds.htm)[2](https://developer.ibm.com/tutorials/awb-using-ibm-granite-llms-in-watsonx-ai-flows-engine)
    """
    try:
        resp = router_agent.run(user_q)
        raw = getattr(resp, "content", None) or str(resp)
        js = _extract_json_object(raw)
        if not js:
            return {"agent": "helpdesk", "confidence": 0.0, "reason": "router_no_json", "secondary_agents": []}
        data = json.loads(js)

        agent = data.get("agent", "helpdesk")
        if agent not in _ALLOWED_AGENT_KEYS:
            agent = "helpdesk"

        try:
            confidence = float(data.get("confidence", 0.0))
        except Exception:
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        reason = str(data.get("reason", ""))[:500]

        sec = data.get("secondary_agents", [])
        if not isinstance(sec, list):
            sec = []
        sec = [a for a in sec if a in _ALLOWED_AGENT_KEYS and a != agent][:2]

        return {"agent": agent, "confidence": confidence, "reason": reason, "secondary_agents": sec}
    except Exception as e:
        return {"agent": "helpdesk", "confidence": 0.0, "reason": f"router_error:{type(e).__name__}", "secondary_agents": []}

def run_agent_and_print(agent: Agent, user_q: str) -> str:
    """
    Use Agent.run() so we can reliably capture output text and print it.
    (print_response() prints but doesn't return content.) [1](https://ibmuser.com/train/dsfolder/ase1ds.htm)[2](https://developer.ibm.com/tutorials/awb-using-ibm-granite-llms-in-watsonx-ai-flows-engine)
    """
    resp = agent.run(user_q)
    content = getattr(resp, "content", None) or str(resp)
    print(content)
    return content


# =============================================================================
# MAIN LOOP
# =============================================================================

def main() -> None:
    _ = get_ibmi_credentials()
    _ = _require_env("ANTHROPIC_API_KEY")

    agents = build_all_agents()
    router = build_router_agent()

    print("\n✅ IBM i Multi-Agent Suite (Model-based Router) is ready.")
    print("\nAvailable agents:")
    for k, a in agents.items():
        print(f" - {k:10s} : {a.name}")
    print("\nUsage tips:")
    print(" - Ask anything normally; LLM router picks the best agent.")
    print(" - Force an agent: /agent security: list risky *PUBLIC authorities")
    print(" - Type 'exit' to quit.\n")

    while True:
        user_q = input("You> ").strip()
        if user_q.lower() in {"exit", "quit"}:
            break
        if not user_q:
            continue

        # Optional manual override
        low = user_q.strip().lower()
        if low.startswith("/agent"):
            rest = user_q.strip()[len("/agent"):].strip()
            key = "helpdesk"
            for k in _ALLOWED_AGENT_KEYS:
                if rest.lower().startswith(k):
                    key = k
                    # remove prefix like "security:" if present
                    user_q = rest[len(k):].lstrip()
                    if user_q.startswith(":"):
                        user_q = user_q[1:].lstrip()
                    break
            agent = agents.get(key, agents["helpdesk"])
            print(f"\n[Routing -> {key} | {agent.name} | manual_override]\n")
            run_agent_and_print(agent, user_q)
            continue

        route = route_question_llm(user_q, router)
        key = route["agent"]
        agent = agents.get(key, agents["helpdesk"])

        print(f"\n[Routing -> {key} | {agent.name} | conf={route['confidence']:.2f} | reason={route['reason']}]\n")
        primary_out = run_agent_and_print(agent, user_q)

        # Optional secondary help (multi-intent)
        for sk in route.get("secondary_agents", []):
            sec_agent = agents.get(sk)
            if not sec_agent:
                continue
            print(f"\n[Secondary -> {sk} | {sec_agent.name}]\n")
            followup = dedent(f"""
            The user asked: {user_q}

            The primary agent responded:
            {primary_out}

            Provide additional evidence or next steps from your specialty.
            """).strip()
            run_agent_and_print(sec_agent, followup)


if __name__ == "__main__":
    main()
