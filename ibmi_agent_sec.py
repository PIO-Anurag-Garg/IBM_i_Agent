
import os
import re
import json
from datetime import datetime, timezone
from textwrap import dedent
from typing import Any, Dict, Optional, List

from dotenv import load_dotenv
from mapepire_python import connect
from pep249 import QueryParameters

from agno.agent import Agent
from agno.models.anthropic import Claude
from agno.tools import tool

load_dotenv()

# =============================================================================
# CONFIG
# =============================================================================

REPORT_BASE_DIR = os.getenv("REPORT_BASE_DIR", "/tmp/ibmi_audit_reports").rstrip("/")
DEFAULT_REPORT_TO = os.getenv("DEFAULT_REPORT_TO", "")
DEFAULT_REPORT_FROM_HINT = os.getenv("IBMI_USER", "")  # for SMTP enrollment hint

# Allow only these report types to be generated/emailed (no arbitrary SQL)
ALLOWED_REPORTS = {
    "autl_drift": "AUTL drift report (baseline vs current)",
    "autl_inventory": "Inventory of authorization lists",
    "users_allobj": "Users with *ALLOBJ",
    "invalid_signons": "Users with invalid sign-on attempts",
    "system_value_changes": "Audit journal SV: system value changes",
    "licenses_expiring": "Licenses expiring within N days",
}

# =============================================================================
# ENV / CONNECTION
# =============================================================================

def _require_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Set it in your shell or in a .env mechanism."
        )
    return value


def get_ibmi_credentials() -> Dict[str, Any]:
    creds: Dict[str, Any] = {
        "host": _require_env("IBMI_HOST"),
        "port": int(_require_env("IBMI_PORT", "8076")),
        "user": _require_env("IBMI_USER"),
        "password": _require_env("IBMI_PASSWORD"),
    }
    ignore_unauth = os.getenv("IBMI_IGNORE_UNAUTHORIZED", "").strip().lower()
    if ignore_unauth in {"1", "true", "yes", "y"}:
        creds["ignoreUnauthorized"] = True
    return creds


def format_mapepire_result(result: Any) -> str:
    try:
        return json.dumps(result, indent=2, default=str)
    except Exception:
        return str(result)


def _extract_sqlstate(exc: Exception) -> Optional[str]:
    for attr in ("sqlstate", "SQLSTATE", "state"):
        if hasattr(exc, attr):
            v = getattr(exc, attr)
            if v:
                return str(v)
    try:
        msg = " ".join(str(a) for a in getattr(exc, "args", []) if a is not None)
        m = re.search(r"\bSQLSTATE\s*=?\s*([0-9A-Z]{5})\b", msg, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    except Exception:
        pass
    return None


def run_sql_statement(
    sql: str,
    parameters: Optional[QueryParameters] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> str:
    creds = creds or get_ibmi_credentials()
    try:
        with connect(creds) as conn:
            with conn.execute(sql, parameters=parameters) as cur:
                if getattr(cur, "has_results", False):
                    raw = cur.fetchall()
                    if isinstance(raw, dict) and "data" in raw:
                        return format_mapepire_result(raw["data"])
                    return format_mapepire_result(raw)
                return "SQL executed successfully. No results returned."
    except Exception as e:
        return format_mapepire_result({
            "error": "SQL execution failed",
            "error_type": type(e).__name__,
            "message": str(e),
            "sqlstate": _extract_sqlstate(e),
            "sql_preview": (sql[:3500] + "…") if len(sql) > 3500 else sql,
            "parameters": parameters,
        })


# =============================================================================
# SAFETY HELPERS
# =============================================================================

_SAFE_IDENT = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)
_SAFE_LIKE = re.compile(r"^[A-Z0-9_ %*]+$", re.IGNORECASE)
_SAFE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SAFE_IFS = re.compile(r"^\/[A-Za-z0-9_\-\/\.]{1,180}$")  # conservative IFS absolute path
_SAFE_JOBQ = re.compile(r"^\*$|^\d{1,6}\/[A-Z0-9_#$@]{1,10}\/[A-Z0-9_#$@]{1,10}$", re.IGNORECASE)
_SAFE_OUTQ = re.compile(r"^(\*ALL|\*LIBL\/[A-Z0-9_#$@]{1,10}|[A-Z0-9_#$@]{1,10}\/[A-Z0-9_#$@]{1,10})$", re.IGNORECASE)
_SAFE_STAR_TOKEN = re.compile(r"^\*[A-Z0-9]+$", re.IGNORECASE)

def _safe_ident(value: str, what: str = "identifier") -> str:
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()

def _safe_limit(n: int, default: int = 10, max_n: int = 200) -> int:
    try:
        n = int(n)
    except Exception:
        return default
    return max(1, min(n, max_n))

def _safe_like_pattern(p: str, default: str = "%") -> str:
    p = (p or "").strip()
    if not p:
        return default
    if not _SAFE_LIKE.match(p):
        raise ValueError(f"Invalid LIKE pattern: {p!r}")
    return p.replace("*", "%").upper()

def _safe_job_name(job_name: str) -> str:
    j = (job_name or "").strip()
    if not j:
        return "*"
    if not _SAFE_JOBQ.match(j):
        raise ValueError("Invalid job_name. Use '*' or '123456/USER/JOBNAME'.")
    return j.upper()

def _safe_outq_qual(q: str) -> str:
    q = (q or "").strip()
    if not q:
        return "*ALL"
    if not _SAFE_OUTQ.match(q):
        raise ValueError("Invalid output queue. Use '*ALL', '*LIBL/OUTQ', or 'LIB/OUTQ'.")
    return q.upper()

def _safe_spooled_status_list(statuses: str) -> str:
    s = (statuses or "").strip()
    if not s:
        return "*ALL"
    toks = s.split()
    if len(toks) == 1 and toks[0].upper() == "*ALL":
        return "*ALL"
    for t in toks:
        if not _SAFE_STAR_TOKEN.match(t):
            raise ValueError("Invalid status token. Use like '*READY *HELD' or '*ALL'.")
    return " ".join(t.upper() for t in toks)

def _safe_user_selector(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return "*CURRENT"
    up = u.upper()
    if up in {"*CURRENT", "*ALL"}:
        return up
    return _safe_ident(u, what="user profile")

def _safe_email(addr: str) -> str:
    a = (addr or "").strip()
    if not a or not _SAFE_EMAIL.match(a):
        raise ValueError(f"Invalid email address: {addr!r}")
    return a

def _safe_ifs_path(path: str) -> str:
    p = (path or "").strip()
    if not p or not _SAFE_IFS.match(p):
        raise ValueError(f"Invalid IFS path: {path!r}")
    return p

def _sql_quote_literal(s: str) -> str:
    """SQL single-quote literal escaping."""
    return "'" + (s or "").replace("'", "''") + "'"

def run_select(sql: str, parameters: Optional[QueryParameters] = None) -> str:
    head = (sql or "").lstrip().upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise ValueError("Only SELECT/WITH statements are allowed by run_select.")
    return run_sql_statement(sql, parameters=parameters)

def run_whitelisted_admin_statement(sql: str) -> str:
    """
    Allow-list for non-SELECT statements used in automation.
    We allow only:
      - VALUES SYSTOOLS.GENERATE_SPREADSHEET(...)
      - VALUES SYSTOOLS.SEND_EMAIL(...)
      - CALL SYSTOOLS.LICENSE_EXPIRATION_CHECK(...)
      - CALL QSYS2.QCMDEXC('QSYS/ADDUSRSMTP ...')   (optional helper)
      - DDL for baseline tables (fixed CREATE statements only)
    """
    s = (sql or "").lstrip()
    u = s.upper()

    allowed_prefixes = (
        "VALUES SYSTOOLS.GENERATE_SPREADSHEET",
        "VALUES SYSTOOLS.SEND_EMAIL",
        "CALL SYSTOOLS.LICENSE_EXPIRATION_CHECK",
        "CALL QSYS2.QCMDEXC",
        "CREATE TABLE SAMPLE.AUTL_BASELINE_ENTRIES",
        "CREATE TABLE SAMPLE.AUTL_BASELINE_OBJECTS",
        "CREATE TABLE SAMPLE.AUTL_BASELINE_RUNS",
        "INSERT INTO SAMPLE.AUTL_BASELINE_RUNS",
        "INSERT INTO SAMPLE.AUTL_BASELINE_ENTRIES",
        "INSERT INTO SAMPLE.AUTL_BASELINE_OBJECTS",
    )
    if not u.startswith(allowed_prefixes):
        raise ValueError("This statement is not whitelisted for execution.")
    return run_sql_statement(sql)

def _ok_if_exists(result_json: str) -> str:
    """
    If CREATE TABLE fails because it already exists, treat as success.
    Db2 SQLSTATE for 'object already exists' is typically 42710.
    """
    try:
        obj = json.loads(result_json)
        if isinstance(obj, dict) and obj.get("error_type") and obj.get("sqlstate") == "42710":
            return format_mapepire_result({"status": "ok", "note": "Object already exists", "details": obj})
    except Exception:
        pass
    return result_json


# =============================================================================
# SQL QUERIES (READ-ONLY)
# =============================================================================

SMOKE_TEST_SQL_1 = "SELECT CURRENT_DATE AS TODAY, CURRENT_USER AS ME, CURRENT_SERVER AS DB FROM SYSIBM.SYSDUMMY1"
SMOKE_TEST_SQL_2 = "SELECT SERVICE_NAME, SERVICE_CATEGORY FROM QSYS2.SERVICES_INFO FETCH FIRST 5 ROWS ONLY"

SERVICES_SEARCH_SQL = """
SELECT SERVICE_CATEGORY, SERVICE_SCHEMA_NAME, SERVICE_NAME, SQL_OBJECT_TYPE, EARLIEST_POSSIBLE_RELEASE
FROM QSYS2.SERVICES_INFO
WHERE (UPPER(SERVICE_NAME) LIKE UPPER(?) OR UPPER(SERVICE_CATEGORY) LIKE UPPER(?))
ORDER BY SERVICE_CATEGORY, SERVICE_SCHEMA_NAME, SERVICE_NAME
FETCH FIRST ? ROWS ONLY
"""

SYSTEM_STATUS_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS(RESET_STATISTICS=>'YES', DETAILED_INFO=>'ALL')) X"
SYSTEM_ACTIVITY_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_ACTIVITY_INFO())"

TOP_CPU_JOBS_SQL = """
SELECT JOB_NAME, AUTHORIZATION_NAME AS USER_NAME, SUBSYSTEM, JOB_STATUS, JOB_TYPE,
       CPU_TIME, TEMPORARY_STORAGE, SQL_STATEMENT_TEXT
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
SELECT JOB_NAME, AUTHORIZATION_NAME AS USER_NAME, SUBSYSTEM, FUNCTION, JOB_STATUS, CPU_TIME
FROM TABLE(QSYS2.ACTIVE_JOB_INFO(DETAILED_INFO => 'WORK')) X
WHERE JOB_STATUS = 'MSGW'
ORDER BY SUBSYSTEM, CPU_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

ASP_INFO_SQL = "SELECT * FROM QSYS2.ASP_INFO ORDER BY ASP_NUMBER"

DISK_HOTSPOTS_SQL = """
SELECT ASP_NUMBER, RESOURCE_NAME, SERIAL_NUMBER, HARDWARE_STATUS, RESOURCE_STATUS,
       PERCENT_USED, UNIT_SPACE_AVAILABLE_GB, TOTAL_READ_REQUESTS, TOTAL_WRITE_REQUESTS
FROM QSYS2.SYSDISKSTAT
ORDER BY PERCENT_USED DESC
FETCH FIRST ? ROWS ONLY
"""

OUTQ_HOTSPOTS_SQL = """
SELECT OUTPUT_QUEUE_LIBRARY_NAME AS OUTQ_LIB, OUTPUT_QUEUE_NAME AS OUTQ,
       NUMBER_OF_FILES, OUTPUT_QUEUE_STATUS, NUMBER_OF_WRITERS
FROM QSYS2.OUTPUT_QUEUE_INFO
ORDER BY NUMBER_OF_FILES DESC
FETCH FIRST ? ROWS ONLY
"""

SPLF_LARGEST_SQL = """
SELECT OUTPUT_QUEUE_LIBRARY_NAME AS OUTQ_LIB, OUTPUT_QUEUE_NAME AS OUTQ,
       SPOOLED_FILE_NAME, USER_NAME, STATUS, SIZE, TOTAL_PAGES, CREATE_TIMESTAMP, JOB_NAME
FROM QSYS2.OUTPUT_QUEUE_ENTRIES_BASIC
ORDER BY SIZE DESC
FETCH FIRST ? ROWS ONLY
"""

NETSTAT_SUMMARY_SQL = """
SELECT LOCAL_ADDRESS, LOCAL_PORT, REMOTE_ADDRESS, REMOTE_PORT, CONNECTION_STATE, IDLE_TIME
FROM QSYS2.NETSTAT_INFO
ORDER BY IDLE_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

NETSTAT_BY_JOB_SQL = """
SELECT CONNECTION_TYPE, LOCAL_ADDRESS, LOCAL_PORT, LOCAL_PORT_NAME,
       REMOTE_ADDRESS, REMOTE_PORT, REMOTE_PORT_NAME,
       AUTHORIZATION_NAME, JOB_NAME, JOB_NAME_SHORT, JOB_USER, JOB_NUMBER
FROM QSYS2.NETSTAT_JOB_INFO
WHERE ( ? IS NULL OR LOCAL_PORT = ? )
ORDER BY LOCAL_PORT, JOB_NAME
FETCH FIRST ? ROWS ONLY
"""

TOP_USER_STORAGE_SQL = """
SELECT AUTHORIZATION_NAME,
       ASPGRP,
       STORAGE_USED,
       MAXIMUM_STORAGE_ALLOWED,
       TOTAL_PROFILE_ENTRIES,
       AVAILABLE_PROFILE_ENTRIES
FROM QSYS2.USER_STORAGE
WHERE ASPGRP = '*SYSBAS'
ORDER BY STORAGE_USED DESC
FETCH FIRST ? ROWS ONLY
"""

USERS_WITH_SPECIAL_AUTH_SQL = """
SELECT AUTHORIZATION_NAME,
       STATUS,
       USER_CLASS_NAME,
       SPECIAL_AUTHORITIES,
       SIGN_ON_ATTEMPTS_NOT_VALID,
       NETSERVER_DISABLED,
       TEXT_DESCRIPTION,
       GROUP_PROFILE_NAME,
       SUPPLEMENTAL_GROUP_LIST
FROM QSYS2.USER_INFO_BASIC
WHERE SPECIAL_AUTHORITIES LIKE ?
ORDER BY AUTHORIZATION_NAME
FETCH FIRST ? ROWS ONLY
"""

USERS_WITH_INVALID_SIGNONS_SQL = """
SELECT AUTHORIZATION_NAME,
       STATUS,
       USER_CLASS_NAME,
       SIGN_ON_ATTEMPTS_NOT_VALID,
       PREVIOUS_SIGNON,
       TEXT_DESCRIPTION
FROM QSYS2.USER_INFO_BASIC
WHERE SIGN_ON_ATTEMPTS_NOT_VALID > 0
ORDER BY SIGN_ON_ATTEMPTS_NOT_VALID DESC
FETCH FIRST ? ROWS ONLY
"""

SYSTEM_VALUES_FILTER_SQL = """
SELECT SYSTEM_VALUE_NAME,
       CATEGORY,
       SYSTEM_VALUE,
       SHIPPED_DEFAULT_VALUE,
       TEXT_DESCRIPTION,
       CHANGEABLE
FROM QSYS2.SYSTEM_VALUE_INFO
WHERE UPPER(SYSTEM_VALUE_NAME) LIKE UPPER(?)
ORDER BY SYSTEM_VALUE_NAME
FETCH FIRST ? ROWS ONLY
"""

# DBE / MTI insight
MTI_INFO_SQL = """
SELECT *
FROM TABLE(QSYS2.MTI_INFO(TABLE_SCHEMA => ?, TABLE_NAME => ?)) X
ORDER BY MTI_SIZE DESC
FETCH FIRST ? ROWS ONLY
"""

# AUTL discovery via OBJECT_STATISTICS (fast/simple)
AUTL_INVENTORY_SQL = """
SELECT OBJNAME AS AUTHORIZATION_LIST,
       OBJLIB  AS LIBRARY,
       CHANGE_TIMESTAMP,
       TEXT_DESCRIPTION
FROM TABLE(QSYS2.OBJECT_STATISTICS('QSYS', '*AUTL', '*ALLSIMPLE')) X
ORDER BY OBJNAME
FETCH FIRST ? ROWS ONLY
"""

AUTL_ENTRIES_SQL = """
SELECT AUTHORIZATION_LIST,
       AUTHORIZATION_NAME,
       OBJECT_AUTHORITY,
       AUTHORIZATION_LIST_MANAGEMENT,
       OWNER
FROM QSYS2.AUTHORIZATION_LIST_USER_INFO
WHERE AUTHORIZATION_LIST = ?
ORDER BY AUTHORIZATION_NAME
FETCH FIRST ? ROWS ONLY
"""

AUTL_OBJECTS_SQL = """
SELECT AUTHORIZATION_LIST,
       OBJECT_LIBRARY,
       OBJECT_NAME,
       OBJECT_TYPE,
       TEXT_DESCRIPTION
FROM QSYS2.AUTHORIZATION_LIST_INFO
WHERE AUTHORIZATION_LIST = ?
ORDER BY OBJECT_LIBRARY, OBJECT_NAME
FETCH FIRST ? ROWS ONLY
"""

AUTL_PUBLIC_CHECK_SQL = """
SELECT AUTHORIZATION_LIST,
       AUTHORIZATION_NAME,
       OBJECT_AUTHORITY
FROM QSYS2.AUTHORIZATION_LIST_USER_INFO
WHERE AUTHORIZATION_LIST = ?
  AND AUTHORIZATION_NAME = '*PUBLIC'
"""

AUTL_PUBLIC_MISCONFIG_OBJECTS_SQL = """
SELECT a.AUTHORIZATION_LIST,
       a.OBJECT_LIBRARY,
       a.OBJECT_NAME,
       a.OBJECT_TYPE,
       p.OBJECT_AUTHORITY AS PUBLIC_AUTHORITY,
       p.OWNER
FROM QSYS2.AUTHORIZATION_LIST_INFO a
JOIN QSYS2.OBJECT_PRIVILEGES p
  ON p.SYSTEM_OBJECT_SCHEMA = a.OBJECT_LIBRARY
 AND p.SYSTEM_OBJECT_NAME   = a.OBJECT_NAME
 AND p.OBJECT_TYPE          = a.OBJECT_TYPE
WHERE a.AUTHORIZATION_LIST = ?
  AND p.AUTHORIZATION_NAME = '*PUBLIC'
  AND p.OBJECT_AUTHORITY <> '*AUTL'
ORDER BY p.OBJECT_AUTHORITY, a.OBJECT_LIBRARY, a.OBJECT_NAME
FETCH FIRST ? ROWS ONLY
"""

# Audit Journal: system value changes (SV)
AUDIT_SYSVAL_CHANGES_SQL_TEMPLATE = """
SELECT ENTRY_TIMESTAMP,
       QUALIFIED_JOB_NAME,
       USER_NAME,
       SYSTEM_VALUE,
       NEW_VALUE,
       OLD_VALUE,
       ENTRY_TYPE
FROM TABLE(
    SYSTOOLS.AUDIT_JOURNAL_SV(
        STARTING_TIMESTAMP => CURRENT TIMESTAMP - {days} DAYS
    )
) X
WHERE ENTRY_TYPE = 'A'
ORDER BY ENTRY_TIMESTAMP DESC
FETCH FIRST {limit} ROWS ONLY
"""

# License expiration listing already exists; also optional procedure call
LICENSES_EXPIRING_SQL = """
SELECT INSTALLED,
       EXPIR_DATE,
       GRACE_PRD,
       LICPGM,
       FEATURE,
       RLS_LVL,
       PROC_GROUP,
       CAST(LABEL AS VARCHAR(100) CCSID 37) AS DESCRIPTION
FROM QSYS2.LICENSE_INFO
WHERE (EXPIR_DATE IS NOT NULL AND EXPIR_DATE <= CURRENT DATE + ? DAYS)
ORDER BY EXPIR_DATE ASC
FETCH FIRST ? ROWS ONLY
"""

# =============================================================================
# BASELINE TABLES (Audit automation)
# =============================================================================

DDL_RUNS = """
CREATE TABLE SAMPLE.AUTL_BASELINE_RUNS (
  RUN_ID           BIGINT GENERATED ALWAYS AS IDENTITY,
  RUN_TIMESTAMP    TIMESTAMP NOT NULL DEFAULT CURRENT TIMESTAMP,
  RUN_BY_USER      VARCHAR(128) DEFAULT CURRENT_USER,
  RUN_NOTE         VARCHAR(256)
)
"""

DDL_ENTRIES = """
CREATE TABLE SAMPLE.AUTL_BASELINE_ENTRIES (
  RUN_ID                    BIGINT NOT NULL,
  RUN_TIMESTAMP             TIMESTAMP NOT NULL,
  AUTHORIZATION_LIST        VARCHAR(10) NOT NULL,
  AUTHORIZATION_NAME        VARCHAR(10) NOT NULL,
  OBJECT_AUTHORITY          VARCHAR(12),
  AUTHORIZATION_LIST_MGMT   VARCHAR(3),
  OWNER                     VARCHAR(10)
)
"""

DDL_OBJECTS = """
CREATE TABLE SAMPLE.AUTL_BASELINE_OBJECTS (
  RUN_ID             BIGINT NOT NULL,
  RUN_TIMESTAMP      TIMESTAMP NOT NULL,
  AUTHORIZATION_LIST VARCHAR(10) NOT NULL,
  OBJECT_LIBRARY     VARCHAR(10) NOT NULL,
  OBJECT_NAME        VARCHAR(10) NOT NULL,
  OBJECT_TYPE        VARCHAR(10) NOT NULL,
  TEXT_DESCRIPTION   VARCHAR(100)
)
"""

INSERT_RUN = """
INSERT INTO SAMPLE.AUTL_BASELINE_RUNS (RUN_NOTE)
VALUES (?)
"""

INSERT_ENTRIES_ALL = """
INSERT INTO SAMPLE.AUTL_BASELINE_ENTRIES
(RUN_ID, RUN_TIMESTAMP, AUTHORIZATION_LIST, AUTHORIZATION_NAME, OBJECT_AUTHORITY, AUTHORIZATION_LIST_MGMT, OWNER)
SELECT ?, ?, AUTHORIZATION_LIST, AUTHORIZATION_NAME, OBJECT_AUTHORITY, AUTHORIZATION_LIST_MANAGEMENT, OWNER
FROM QSYS2.AUTHORIZATION_LIST_USER_INFO
"""

INSERT_OBJECTS_ALL = """
INSERT INTO SAMPLE.AUTL_BASELINE_OBJECTS
(RUN_ID, RUN_TIMESTAMP, AUTHORIZATION_LIST, OBJECT_LIBRARY, OBJECT_NAME, OBJECT_TYPE, TEXT_DESCRIPTION)
SELECT ?, ?, AUTHORIZATION_LIST, OBJECT_LIBRARY, OBJECT_NAME, OBJECT_TYPE,
       CAST(TEXT_DESCRIPTION AS VARCHAR(100) CCSID 37)
FROM QSYS2.AUTHORIZATION_LIST_INFO
"""

# Compare latest baseline to current for a given AUTL
AUTL_DRIFT_SQL = """
WITH latest AS (
  SELECT MAX(RUN_TIMESTAMP) AS RUN_TS
  FROM SAMPLE.AUTL_BASELINE_RUNS
),
base_entries AS (
  SELECT e.AUTHORIZATION_LIST, e.AUTHORIZATION_NAME, e.OBJECT_AUTHORITY, e.AUTHORIZATION_LIST_MGMT
  FROM SAMPLE.AUTL_BASELINE_ENTRIES e
  JOIN latest l ON e.RUN_TIMESTAMP = l.RUN_TS
  WHERE e.AUTHORIZATION_LIST = ?
),
curr_entries AS (
  SELECT AUTHORIZATION_LIST, AUTHORIZATION_NAME, OBJECT_AUTHORITY, AUTHORIZATION_LIST_MANAGEMENT AS AUTHORIZATION_LIST_MGMT
  FROM QSYS2.AUTHORIZATION_LIST_USER_INFO
  WHERE AUTHORIZATION_LIST = ?
),
diff_entries AS (
  SELECT
    COALESCE(b.AUTHORIZATION_NAME, c.AUTHORIZATION_NAME) AS AUTHORIZATION_NAME,
    b.OBJECT_AUTHORITY AS BASE_AUTH,
    c.OBJECT_AUTHORITY AS CURR_AUTH,
    b.AUTHORIZATION_LIST_MGMT AS BASE_MGMT,
    c.AUTHORIZATION_LIST_MGMT AS CURR_MGMT,
    CASE
      WHEN b.AUTHORIZATION_NAME IS NULL THEN 'ADDED'
      WHEN c.AUTHORIZATION_NAME IS NULL THEN 'REMOVED'
      WHEN COALESCE(b.OBJECT_AUTHORITY,'') <> COALESCE(c.OBJECT_AUTHORITY,'')
        OR COALESCE(b.AUTHORIZATION_LIST_MGMT,'') <> COALESCE(c.AUTHORIZATION_LIST_MGMT,'')
      THEN 'CHANGED'
      ELSE 'SAME'
    END AS CHANGE_TYPE
  FROM base_entries b
  FULL OUTER JOIN curr_entries c
    ON b.AUTHORIZATION_NAME = c.AUTHORIZATION_NAME
)
SELECT *
FROM diff_entries
WHERE CHANGE_TYPE <> 'SAME'
ORDER BY CHANGE_TYPE, AUTHORIZATION_NAME
FETCH FIRST ? ROWS ONLY
"""

# =============================================================================
# INTERNAL IMPLEMENTATIONS (callable Python functions)
# =============================================================================

def _impl_smoke_test() -> str:
    a = run_select(SMOKE_TEST_SQL_1)
    b = run_select(SMOKE_TEST_SQL_2)
    return format_mapepire_result({"sysdummy1": a, "services_info_sample": b})

def _impl_search_sql_services(keyword: str, limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    like = f"%{(keyword or '').strip()}%"
    return run_select(SERVICES_SEARCH_SQL, parameters=[like, like, lim])

def _impl_get_system_status() -> str:
    return run_select(SYSTEM_STATUS_SQL)

def _impl_get_system_activity() -> str:
    return run_select(SYSTEM_ACTIVITY_SQL)

def _impl_top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    sbs = _safe_csv_idents(subsystem_csv, "subsystems") if subsystem_csv else ""
    usr = _safe_csv_idents(user_csv, "users") if user_csv else ""
    return run_select(TOP_CPU_JOBS_SQL, parameters=[sbs, usr, lim])

def _impl_jobs_in_msgw(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    return run_select(MSGW_JOBS_SQL, parameters=[lim])

def _impl_get_asp_info() -> str:
    return run_select(ASP_INFO_SQL)

def _impl_disk_hotspots(limit: int = 10) -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    return run_select(DISK_HOTSPOTS_SQL, parameters=[lim])

def _impl_output_queue_hotspots(limit: int = 20) -> str:
    lim = _safe_limit(limit, default=20, max_n=500)
    return run_select(OUTQ_HOTSPOTS_SQL, parameters=[lim])

def _impl_largest_spool_files(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=2000)
    return run_select(SPLF_LARGEST_SQL, parameters=[lim])

def _impl_netstat_snapshot(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=2000)
    return run_select(NETSTAT_SUMMARY_SQL, parameters=[lim])

def _impl_netstat_by_job(limit: int = 200, local_port: Optional[int] = None) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    if local_port is None:
        return run_select(NETSTAT_BY_JOB_SQL, parameters=[None, None, lim])
    p = _safe_limit(int(local_port), default=int(local_port), max_n=65535)
    return run_select(NETSTAT_BY_JOB_SQL, parameters=[p, p, lim])

def _impl_top_user_storage(limit: int = 25) -> str:
    lim = _safe_limit(limit, default=25, max_n=1000)
    return run_select(TOP_USER_STORAGE_SQL, parameters=[lim])

def _impl_users_allobj(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(USERS_WITH_SPECIAL_AUTH_SQL, parameters=["%*ALLOBJ%", lim])

def _impl_users_invalid_signons(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(USERS_WITH_INVALID_SIGNONS_SQL, parameters=[lim])

def _impl_system_value_changes(days: int = 30, limit: int = 500) -> str:
    d = _safe_limit(days, default=30, max_n=3650)
    lim = _safe_limit(limit, default=500, max_n=5000)
    sql = AUDIT_SYSVAL_CHANGES_SQL_TEMPLATE.format(days=d, limit=lim)
    return run_select(sql)

def _impl_system_values(pattern: str = "QPWD%", limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    like = _safe_like_pattern(pattern, default="%")
    if "%" not in like:
        like = f"%{like}%"
    return run_select(SYSTEM_VALUES_FILTER_SQL, parameters=[like, lim])

def _impl_mti_hotspots(schema: str = "*ALL", table: str = "*ALL", limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=2000)
    s = (schema or "*ALL").strip().upper()
    t = (table or "*ALL").strip().upper()
    if s != "*ALL":
        s = _safe_ident(s, "schema")
    if t != "*ALL":
        t = _safe_ident(t, "table")
    return run_select(MTI_INFO_SQL, parameters=[s, t, lim])

def _impl_autl_inventory(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(AUTL_INVENTORY_SQL, parameters=[lim])

def _impl_autl_entries(autl: str, limit: int = 500) -> str:
    a = _safe_ident(autl, "AUTL")
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(AUTL_ENTRIES_SQL, parameters=[a, lim])

def _impl_autl_objects(autl: str, limit: int = 500) -> str:
    a = _safe_ident(autl, "AUTL")
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(AUTL_OBJECTS_SQL, parameters=[a, lim])

def _impl_autl_public_check(autl: str) -> str:
    a = _safe_ident(autl, "AUTL")
    return run_select(AUTL_PUBLIC_CHECK_SQL, parameters=[a])

def _impl_autl_public_misconfigured_objects(autl: str, limit: int = 500) -> str:
    a = _safe_ident(autl, "AUTL")
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(AUTL_PUBLIC_MISCONFIG_OBJECTS_SQL, parameters=[a, lim])

def _impl_licenses_expiring(days: int = 30, limit: int = 500) -> str:
    d = _safe_limit(days, default=30, max_n=3650)
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(LICENSES_EXPIRING_SQL, parameters=[d, lim])

# =============================================================================
# AUDIT AUTOMATION: BASELINE CAPTURE + DRIFT
# =============================================================================

def _impl_setup_audit_tables() -> str:
    # Create tables (ignore "already exists")
    r1 = _ok_if_exists(run_whitelisted_admin_statement(DDL_RUNS))
    r2 = _ok_if_exists(run_whitelisted_admin_statement(DDL_ENTRIES))
    r3 = _ok_if_exists(run_whitelisted_admin_statement(DDL_OBJECTS))
    return format_mapepire_result({"runs": r1, "entries": r2, "objects": r3})

def _impl_capture_autl_baseline(note: str = "baseline capture") -> str:
    # Insert a run row, fetch the new RUN_ID and timestamp using IDENTITY_VAL_LOCAL() pattern
    # Approach: insert, then query max RUN_ID (safe because baseline table is local)
    ins = run_sql_statement(INSERT_RUN, parameters=[note])
    # Retrieve last run
    get_last = run_select("SELECT MAX(RUN_ID) AS RUN_ID, MAX(RUN_TIMESTAMP) AS RUN_TIMESTAMP FROM SAMPLE.AUTL_BASELINE_RUNS")
    try:
        last = json.loads(get_last)
        run_id = last[0]["RUN_ID"] if isinstance(last, list) else last.get("RUN_ID")
        run_ts = last[0]["RUN_TIMESTAMP"] if isinstance(last, list) else last.get("RUN_TIMESTAMP")
    except Exception:
        return format_mapepire_result({"error": "Could not resolve RUN_ID after insert", "insert": ins, "select": get_last})

    # Snapshot all AUTL entries + all secured objects
    i1 = run_whitelisted_admin_statement(INSERT_ENTRIES_ALL.replace("SELECT ?, ?", "SELECT ?, ?"),)
    # Mapepire needs parameters; use run_sql_statement directly
    i1 = run_sql_statement(INSERT_ENTRIES_ALL, parameters=[run_id, run_ts])
    i2 = run_sql_statement(INSERT_OBJECTS_ALL, parameters=[run_id, run_ts])

    return format_mapepire_result({
        "run_id": run_id,
        "run_timestamp": run_ts,
        "insert_run_result": ins,
        "insert_entries_result": i1,
        "insert_objects_result": i2
    })

def _impl_autl_drift(autl: str, limit: int = 500) -> str:
    a = _safe_ident(autl, "AUTL")
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(AUTL_DRIFT_SQL, parameters=[a, a, lim])

# =============================================================================
# REPORT AUTOMATION: GENERATE SPREADSHEET + SEND EMAIL
# =============================================================================

def _build_report_query(report_name: str, *, autl: str = "", days: int = 30, limit: int = 1000) -> str:
    """
    Return a safe, pre-defined SQL query string for spreadsheet generation.
    No user-supplied arbitrary SQL allowed.
    """
    report_name = (report_name or "").strip().lower()
    if report_name not in ALLOWED_REPORTS:
        raise ValueError(f"report_name not allowed. Choose one of: {sorted(ALLOWED_REPORTS.keys())}")

    lim = _safe_limit(limit, default=1000, max_n=10000)
    d = _safe_limit(days, default=30, max_n=3650)

    if report_name == "autl_inventory":
        return f"SELECT * FROM TABLE(QSYS2.OBJECT_STATISTICS('QSYS','*AUTL','*ALLSIMPLE')) X FETCH FIRST {lim} ROWS ONLY"

    if report_name == "users_allobj":
        return f"SELECT * FROM QSYS2.USER_INFO_BASIC WHERE SPECIAL_AUTHORITIES LIKE '%*ALLOBJ%' ORDER BY AUTHORIZATION_NAME FETCH FIRST {lim} ROWS ONLY"

    if report_name == "invalid_signons":
        return f"SELECT * FROM QSYS2.USER_INFO_BASIC WHERE SIGN_ON_ATTEMPTS_NOT_VALID > 0 ORDER BY SIGN_ON_ATTEMPTS_NOT_VALID DESC FETCH FIRST {lim} ROWS ONLY"

    if report_name == "system_value_changes":
        return (
            "SELECT ENTRY_TIMESTAMP, QUALIFIED_JOB_NAME, USER_NAME, SYSTEM_VALUE, NEW_VALUE, OLD_VALUE, ENTRY_TYPE "
            f"FROM TABLE(SYSTOOLS.AUDIT_JOURNAL_SV(STARTING_TIMESTAMP => CURRENT TIMESTAMP - {d} DAYS)) X "
            "WHERE ENTRY_TYPE = 'A' "
            f"ORDER BY ENTRY_TIMESTAMP DESC FETCH FIRST {lim} ROWS ONLY"
        )

    if report_name == "licenses_expiring":
        return (
            "SELECT INSTALLED, EXPIR_DATE, GRACE_PRD, LICPGM, FEATURE, RLS_LVL, PROC_GROUP, "
            "CAST(LABEL AS VARCHAR(100) CCSID 37) AS DESCRIPTION "
            "FROM QSYS2.LICENSE_INFO "
            f"WHERE EXPIR_DATE IS NOT NULL AND EXPIR_DATE <= CURRENT DATE + {d} DAYS "
            f"ORDER BY EXPIR_DATE ASC FETCH FIRST {lim} ROWS ONLY"
        )

    if report_name == "autl_drift":
        if not autl:
            raise ValueError("autl is required for autl_drift report")
        a = _safe_ident(autl, "AUTL")
        # Use baseline diff query on server-side baseline tables
        # Spreadsheet query cannot use parameter markers, so inline AUTL safely
        return (
            "WITH latest AS (SELECT MAX(RUN_TIMESTAMP) AS RUN_TS FROM SAMPLE.AUTL_BASELINE_RUNS), "
            "base_entries AS ( "
            "  SELECT e.AUTHORIZATION_LIST, e.AUTHORIZATION_NAME, e.OBJECT_AUTHORITY, e.AUTHORIZATION_LIST_MGMT "
            "  FROM SAMPLE.AUTL_BASELINE_ENTRIES e JOIN latest l ON e.RUN_TIMESTAMP = l.RUN_TS "
            f"  WHERE e.AUTHORIZATION_LIST = '{a}' "
            "), "
            "curr_entries AS ( "
            "  SELECT AUTHORIZATION_LIST, AUTHORIZATION_NAME, OBJECT_AUTHORITY, AUTHORIZATION_LIST_MANAGEMENT AS AUTHORIZATION_LIST_MGMT "
            "  FROM QSYS2.AUTHORIZATION_LIST_USER_INFO "
            f"  WHERE AUTHORIZATION_LIST = '{a}' "
            "), "
            "diff_entries AS ( "
            "  SELECT COALESCE(b.AUTHORIZATION_NAME, c.AUTHORIZATION_NAME) AS AUTHORIZATION_NAME, "
            "         b.OBJECT_AUTHORITY AS BASE_AUTH, c.OBJECT_AUTHORITY AS CURR_AUTH, "
            "         b.AUTHORIZATION_LIST_MGMT AS BASE_MGMT, c.AUTHORIZATION_LIST_MGMT AS CURR_MGMT, "
            "         CASE "
            "           WHEN b.AUTHORIZATION_NAME IS NULL THEN 'ADDED' "
            "           WHEN c.AUTHORIZATION_NAME IS NULL THEN 'REMOVED' "
            "           WHEN COALESCE(b.OBJECT_AUTHORITY,'') <> COALESCE(c.OBJECT_AUTHORITY,'') "
            "             OR COALESCE(b.AUTHORIZATION_LIST_MGMT,'') <> COALESCE(c.AUTHORIZATION_LIST_MGMT,'') "
            "           THEN 'CHANGED' ELSE 'SAME' "
            "         END AS CHANGE_TYPE "
            "  FROM base_entries b FULL OUTER JOIN curr_entries c "
            "    ON b.AUTHORIZATION_NAME = c.AUTHORIZATION_NAME "
            ") "
            "SELECT * FROM diff_entries WHERE CHANGE_TYPE <> 'SAME' "
            f"ORDER BY CHANGE_TYPE, AUTHORIZATION_NAME FETCH FIRST {lim} ROWS ONLY"
        )

    raise ValueError("Unhandled report_name")


def _impl_generate_spreadsheet(report_name: str, *, autl: str = "", days: int = 30,
                              spreadsheet_type: str = "xlsx", limit: int = 1000) -> str:
    """
    Generates a spreadsheet to IFS using SYSTOOLS.GENERATE_SPREADSHEET.
    """
    report_name = (report_name or "").strip().lower()
    spreadsheet_type = (spreadsheet_type or "xlsx").strip().lower()
    if spreadsheet_type not in {"xlsx", "csv", "ods"}:
        raise ValueError("spreadsheet_type must be one of: xlsx, csv, ods")

    query = _build_report_query(report_name, autl=autl, days=days, limit=limit)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"{REPORT_BASE_DIR}/{report_name}_{stamp}"
    path_name = _safe_ifs_path(base)

    sql = (
        "VALUES SYSTOOLS.GENERATE_SPREADSHEET("
        f"PATH_NAME => {_sql_quote_literal(path_name)}, "
        f"SPREADSHEET_QUERY => {_sql_quote_literal(query)}, "
        f"SPREADSHEET_TYPE => {_sql_quote_literal(spreadsheet_type)}, "
        "COLUMN_HEADINGS => 'COLUMN'"
        ")"
    )
    res = run_whitelisted_admin_statement(sql)

    return format_mapepire_result({
        "result": res,
        "ifs_path_no_ext": path_name,
        "expected_file": f"{path_name}.{spreadsheet_type}",
        "report_name": report_name
    })


def _impl_send_email(to_email: str, subject: str, body: str, attachment_path: Optional[str] = None,
                     body_type: str = "*PLAIN") -> str:
    """
    Sends email using SYSTOOLS.SEND_EMAIL.
    Assumes the user is registered to SMTP via ADDUSRSMTP as required by SEND_EMAIL documentation.
    """
    to_email = _safe_email(to_email)
    subject = (subject or "")[:255]
    body = (body or "")[:5000]
    body_type = (body_type or "*PLAIN").strip().upper()
    if body_type not in {"*PLAIN", "*HTML", "*XML"}:
        body_type = "*PLAIN"

    attach_clause = ""
    if attachment_path:
        ap = _safe_ifs_path(attachment_path)
        attach_clause = f", ATTACHMENT => {_sql_quote_literal(ap)}"

    sql = (
        "VALUES SYSTOOLS.SEND_EMAIL("
        f"TO_EMAIL => {_sql_quote_literal(to_email)}, "
        f"SUBJECT => {_sql_quote_literal(subject)}, "
        f"BODY => {_sql_quote_literal(body)}"
        f"{attach_clause}, "
        f"BODY_TYPE => {_sql_quote_literal(body_type)}"
        ")"
    )
    return run_whitelisted_admin_statement(sql)


def _impl_generate_and_email_report(
    report_name: str,
    to_email: str = "",
    autl: str = "",
    days: int = 30,
    spreadsheet_type: str = "xlsx",
    limit: int = 1000,
    subject_prefix: str = "[IBM i Audit]",
) -> str:
    if not to_email:
        if not DEFAULT_REPORT_TO:
            raise ValueError("to_email not provided and DEFAULT_REPORT_TO is not set.")
        to_email = DEFAULT_REPORT_TO

    gen = json.loads(_impl_generate_spreadsheet(report_name, autl=autl, days=days, spreadsheet_type=spreadsheet_type, limit=limit))
    attachment = gen["expected_file"]
    subj = f"{subject_prefix} {report_name}"
    if autl:
        subj += f" AUTL={autl}"
    body = f"Attached report '{report_name}'. Generated at UTC. File: {attachment}"
    sent = _impl_send_email(to_email, subj, body, attachment_path=attachment, body_type="*PLAIN")
    return format_mapepire_result({"generated": gen, "email_result": sent})


def _impl_ensure_smtp_user(user_profile: str = "") -> str:
    """
    Optional helper: enroll the current (or specified) user to SMTP using ADDUSRSMTP via QSYS2.QCMDEXC.
    SEND_EMAIL assumes this enrollment. Use with care.
    """
    u = _safe_ident(user_profile or _require_env("IBMI_USER"), "user profile")
    cmd = f"QSYS/ADDUSRSMTP USRPRF({u})"
    sql = f"CALL QSYS2.QCMDEXC({_sql_quote_literal(cmd)})"
    return run_whitelisted_admin_statement(sql)


def _impl_call_license_expiration_check(days: int = 30) -> str:
    """
    Calls SYSTOOLS.LICENSE_EXPIRATION_CHECK which sends messages to QSYSOPR. (Optional push alert)
    """
    d = _safe_limit(days, default=30, max_n=3650)
    sql = f"CALL SYSTOOLS.LICENSE_EXPIRATION_CHECK({d})"
    return run_whitelisted_admin_statement(sql)


# =============================================================================
# TRIAGE META TOOL (ops + optional security audit automation quick-check)
# =============================================================================

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _section(title: str, body: str) -> str:
    body = (body or "").strip()
    if not body:
        body = "_(no data)_"
    return f"\n\n## {title}\n\n```json\n{body}\n```"

def _safe_call(name: str, fn, *args, **kwargs) -> str:
    try:
        out = fn(*args, **kwargs)
        return out if isinstance(out, str) else format_mapepire_result(out)
    except Exception as e:
        return format_mapepire_result({"error": f"{name} failed", "details": str(e)})

@tool(
    name="triage-now",
    description="Ops triage report. Optionally include security sections: users_allobj, sysval_changes, autl_public_drift."
)
def triage_now(netstat_port: Optional[int] = None, include_security: int = 0, autl: str = "") -> str:
    started = _utc_now_iso()

    smoke = _safe_call("smoke-test", _impl_smoke_test)
    sys_status = _safe_call("system-status", _impl_get_system_status)
    sys_activity = _safe_call("system-activity", _impl_get_system_activity)
    topcpu = _safe_call("top-cpu-jobs", _impl_top_cpu_jobs, 10, "", "")
    msgw = _safe_call("msgw", _impl_jobs_in_msgw, 50)
    asp = _safe_call("asp", _impl_get_asp_info)
    disks = _safe_call("disks", _impl_disk_hotspots, 10)
    outqs = _safe_call("outqs", _impl_output_queue_hotspots, 20)
    spl = _safe_call("largest-spool", _impl_largest_spool_files, 25)
    net = _safe_call("netstat", _impl_netstat_snapshot, 50)
    net_by_job = _safe_call("netstat-by-job", _impl_netstat_by_job, 500, netstat_port)
    user_stg = _safe_call("user-storage", _impl_top_user_storage, 20)
    mti = _safe_call("mti", _impl_mti_hotspots, "*ALL", "*ALL", 25)

    sec = ""
    if int(include_security) == 1:
        sec += _section("SEC: Users with *ALLOBJ", _safe_call("users_allobj", _impl_users_allobj, 500))
        sec += _section("SEC: System value changes (last 30 days)", _safe_call("sysval_changes", _impl_system_value_changes, 30, 500))
        if autl:
            sec += _section(f"SEC: AUTL *PUBLIC check ({autl})", _safe_call("autl_public", _impl_autl_public_check, autl))
            sec += _section(f"SEC: AUTL objects where *PUBLIC != *AUTL ({autl})", _safe_call("autl_pub_drift", _impl_autl_public_misconfigured_objects, autl, 500))

    finished = _utc_now_iso()

    report = f"""# IBM i Ops Triage Report

- **Started (UTC):** {started}
- **Finished (UTC):** {finished}
"""
    report += _section("Smoke Test", smoke)
    report += _section("System Status", sys_status)
    report += _section("System Activity", sys_activity)
    report += _section("Top CPU Jobs", topcpu)
    report += _section("MSGW Jobs", msgw)
    report += _section("ASP Info", asp)
    report += _section("Disk Hotspots", disks)
    report += _section("Output Queue Hotspots", outqs)
    report += _section("Largest Spooled Files", spl)
    report += _section("Netstat Snapshot", net)
    report += _section("Netstat By Job", net_by_job)
    report += _section("Top User Storage", user_stg)
    report += _section("MTI Hotspots", mti)

    if sec:
        report += "\n\n# Security Addendum\n" + sec

    return report


# =============================================================================
# TOOL WRAPPERS (Everything else)
# =============================================================================

@tool(name="smoke-test", description="Connectivity + QSYS2 access smoke test.")
def smoke_test() -> str:
    return _impl_smoke_test()

@tool(name="search-sql-services", description="Search IBM i SQL services catalog by keyword.")
def search_sql_services(keyword: str, limit: int = 50) -> str:
    return _impl_search_sql_services(keyword, limit)

@tool(name="get-system-status", description="Overall IBM i performance snapshot (SYSTEM_STATUS).")
def get_system_status() -> str:
    return _impl_get_system_status()

@tool(name="get-system-activity", description="IBM i activity snapshot (SYSTEM_ACTIVITY_INFO).")
def get_system_activity() -> str:
    return _impl_get_system_activity()

@tool(name="top-cpu-jobs", description="Top CPU consuming jobs.")
def top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    return _impl_top_cpu_jobs(limit, subsystem_csv, user_csv)

@tool(name="jobs-in-msgw", description="Jobs in MSGW (message wait).")
def jobs_in_msgw(limit: int = 50) -> str:
    return _impl_jobs_in_msgw(limit)

@tool(name="get-asp-info", description="ASP info.")
def get_asp_info() -> str:
    return _impl_get_asp_info()

@tool(name="disk-hotspots", description="Disk hotspots (highest percent used).")
def disk_hotspots(limit: int = 10) -> str:
    return _impl_disk_hotspots(limit)

@tool(name="output-queue-hotspots", description="Output queues with most spooled files.")
def output_queue_hotspots(limit: int = 20) -> str:
    return _impl_output_queue_hotspots(limit)

@tool(name="largest-spool-files", description="Largest spool files system-wide.")
def largest_spool_files(limit: int = 50) -> str:
    return _impl_largest_spool_files(limit)

@tool(name="netstat-snapshot", description="Netstat snapshot.")
def netstat_snapshot(limit: int = 50) -> str:
    return _impl_netstat_snapshot(limit)

@tool(name="netstat-by-job", description="Netstat by job; optional port filter.")
def netstat_by_job(limit: int = 200, local_port: Optional[int] = None) -> str:
    return _impl_netstat_by_job(limit, local_port)

@tool(name="top-user-storage", description="Top user storage consumers.")
def top_user_storage(limit: int = 25) -> str:
    return _impl_top_user_storage(limit)

@tool(name="users-allobj", description="Users with *ALLOBJ (fast).")
def users_allobj(limit: int = 500) -> str:
    return _impl_users_allobj(limit)

@tool(name="users-invalid-signons", description="Users with invalid sign-on attempts.")
def users_invalid_signons(limit: int = 200) -> str:
    return _impl_users_invalid_signons(limit)

@tool(name="system-value-changes", description="Audit Journal SV: system value changes for last N days.")
def system_value_changes(days: int = 30, limit: int = 500) -> str:
    return _impl_system_value_changes(days, limit)

@tool(name="system-values", description="Query system values by pattern (e.g. QPWD%).")
def system_values(pattern: str = "QPWD%", limit: int = 200) -> str:
    return _impl_system_values(pattern, limit)

@tool(name="mti-hotspots", description="MTI hotspots (Maintained Temporary Indexes).")
def mti_hotspots(schema: str = "*ALL", table: str = "*ALL", limit: int = 50) -> str:
    return _impl_mti_hotspots(schema, table, limit)

@tool(name="autl-inventory", description="List AUTLs on system.")
def autl_inventory(limit: int = 500) -> str:
    return _impl_autl_inventory(limit)

@tool(name="autl-entries", description="List entries in an AUTL.")
def autl_entries(autl: str, limit: int = 500) -> str:
    return _impl_autl_entries(autl, limit)

@tool(name="autl-objects", description="List objects secured by an AUTL.")
def autl_objects(autl: str, limit: int = 500) -> str:
    return _impl_autl_objects(autl, limit)

@tool(name="autl-public-check", description="Check *PUBLIC authority for an AUTL.")
def autl_public_check(autl: str) -> str:
    return _impl_autl_public_check(autl)

@tool(name="autl-public-misconfigured-objects", description="Objects under an AUTL where *PUBLIC is not *AUTL.")
def autl_public_misconfigured_objects(autl: str, limit: int = 500) -> str:
    return _impl_autl_public_misconfigured_objects(autl, limit)

@tool(name="licenses-expiring", description="Licenses expiring within N days (view-based).")
def licenses_expiring(days: int = 30, limit: int = 500) -> str:
    return _impl_licenses_expiring(days, limit)

# ----------------------------
# AUTOMATION TOOLS
# ----------------------------

@tool(name="setup-audit-tables", description="Create baseline tables in SAMPLE for AUTL baseline/drift automation (idempotent).")
def setup_audit_tables() -> str:
    return _impl_setup_audit_tables()

@tool(name="capture-autl-baseline", description="Capture baseline snapshot of all AUTL entries + secured objects into SAMPLE baseline tables.")
def capture_autl_baseline(note: str = "baseline capture") -> str:
    return _impl_capture_autl_baseline(note)

@tool(name="autl-drift", description="Compare AUTL to latest baseline snapshot and return changes (added/removed/changed).")
def autl_drift(autl: str, limit: int = 500) -> str:
    return _impl_autl_drift(autl, limit)

@tool(name="generate-spreadsheet-report", description="Generate a whitelisted audit report to IFS using SYSTOOLS.GENERATE_SPREADSHEET.")
def generate_spreadsheet_report(report_name: str, autl: str = "", days: int = 30, spreadsheet_type: str = "xlsx", limit: int = 1000) -> str:
    return _impl_generate_spreadsheet(report_name, autl=autl, days=days, spreadsheet_type=spreadsheet_type, limit=limit)

@tool(name="send-email", description="Send email via SYSTOOLS.SEND_EMAIL (SMTP user must be enrolled).")
def send_email(to_email: str, subject: str, body: str, attachment_path: str = "", body_type: str = "*PLAIN") -> str:
    return _impl_send_email(to_email, subject, body, attachment_path or None, body_type)

@tool(name="generate-and-email-report", description="Generate a whitelisted audit report (csv/xlsx/ods) and email it as attachment.")
def generate_and_email_report(report_name: str, to_email: str = "", autl: str = "", days: int = 30, spreadsheet_type: str = "xlsx", limit: int = 1000) -> str:
    return _impl_generate_and_email_report(report_name, to_email, autl, days, spreadsheet_type, limit)

@tool(name="ensure-smtp-user", description="(Optional) Enroll a user for SMTP using ADDUSRSMTP via QCMDEXC so SEND_EMAIL can work.")
def ensure_smtp_user(user_profile: str = "") -> str:
    return _impl_ensure_smtp_user(user_profile)

@tool(name="license-expiration-check", description="(Optional) CALL SYSTOOLS.LICENSE_EXPIRATION_CHECK(days) to push QSYSOPR messages.")
def license_expiration_check(days: int = 30) -> str:
    return _impl_call_license_expiration_check(days)

# =============================================================================
# AGENT
# =============================================================================

def build_agent() -> Agent:
    model_id = os.getenv("CLAUDE_MODEL_ID", "claude-sonnet-4-5-20250929")

    return Agent(
        name="IBM i 7.5 Audit Automation Assistant (AUTL-first)",
        model=Claude(id=model_id),
        tools=[
            # Meta triage
            triage_now,

            # Connectivity
            smoke_test,

            # Ops
            get_system_status,
            get_system_activity,
            top_cpu_jobs,
            jobs_in_msgw,
            get_asp_info,
            disk_hotspots,
            output_queue_hotspots,
            largest_spool_files,
            netstat_snapshot,
            netstat_by_job,
            top_user_storage,
            mti_hotspots,

            # Security visibility
            autl_inventory,
            autl_entries,
            autl_objects,
            autl_public_check,
            autl_public_misconfigured_objects,
            users_allobj,
            users_invalid_signons,
            system_value_changes,
            system_values,
            licenses_expiring,

            # Audit automation
            setup_audit_tables,
            capture_autl_baseline,
            autl_drift,
            generate_spreadsheet_report,
            send_email,
            generate_and_email_report,
            ensure_smtp_user,
            license_expiration_check,

            # Discovery
            search_sql_services,
        ],
        instructions=dedent(
            f"""
            You are an expert IBM i 7.5 operations + AUTL-first security audit automation assistant.

            Safety rules:
            - Use ONLY provided tools. Do not run arbitrary SQL from the user.
            - Report generation/email is allowed only via whitelisted report templates.

            Audit automation workflow:
            1) First time: run 'setup-audit-tables'
            2) Establish baseline: run 'capture-autl-baseline'
            3) Drift check: run 'autl-drift' for specific AUTLs
            4) Export evidence: run 'generate-spreadsheet-report' (or 'generate-and-email-report')

            Report delivery:
            - Spreadsheet reports are generated to IFS using SYSTOOLS.GENERATE_SPREADSHEET and emailed using SYSTOOLS.SEND_EMAIL.
            - SEND_EMAIL requires the user to be registered to SMTP (ADDUSRSMTP). Use 'ensure-smtp-user' if appropriate.
            - Report directory base is: {REPORT_BASE_DIR}
            - Default email recipient (if configured) is: {DEFAULT_REPORT_TO or "(not set)"}

            Answer style:
            - Provide Summary -> Evidence -> Recommended Actions.
            """
        ).strip(),
        markdown=True,
    )


def main():
    _ = get_ibmi_credentials()
    _ = _require_env("ANTHROPIC_API_KEY")

    agent = build_agent()

    print("\n✅ IBM i 7.5 Audit Automation Agent is ready.")
    print("\nSuggested commands:")
    print(" - smoke test")
    print(" - setup audit tables")
    print(" - capture autl baseline")
    print(" - autl drift PAYROLL")
    print(" - generate spreadsheet report autl_inventory")
    print(" - generate and email report system_value_changes to_email=security@company.com days=30 spreadsheet_type=xlsx")
    print(" - triage now include_security=1 autl=PAYROLL")
    print("\nType a question (or 'exit' to quit).\n")

    while True:
        user_q = input("You> ").strip()
        if user_q.lower() in {"exit", "quit"}:
            break
        if not user_q:
            continue
        agent.print_response(user_q)


if __name__ == "__main__":
    main()