# ibmi_parallel_agent.py - Parallel Sub-Agent Architecture for IBM i
# Uses ThreadPoolExecutor for parallel execution to reduce response time by 3-4x
# Combines 70+ tools from ibmi_agent.py with streaming UI from new_IBMi_agent.py

import os
import re
import sys
import json
import time
import threading
from textwrap import dedent
from typing import Any, Dict, Optional, List, Tuple, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed, Future, TimeoutError
from enum import Enum

# Fix Windows console encoding for emojis and markdown
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except:
        pass

from dotenv import load_dotenv
from mapepire_python import connect
from pep249 import QueryParameters

from agno.agent import Agent, RunEvent, RunOutputEvent
from agno.models.openrouter import OpenRouter
from agno.tools import tool

# Import rich for UI
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich import box
    _console = Console()
    _has_rich = True
except ImportError:
    _has_rich = False
    _console = None

# =============================================================================
# ENVIRONMENT & CONFIGURATION
# =============================================================================

load_dotenv()

def _require_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value

def get_ibmi_credentials() -> Dict[str, Any]:
    creds: Dict[str, Any] = {
        "host": _require_env("IBMI_HOST"),
        "port": int(_require_env("IBMI_PORT", "8076")),
        "user": _require_env("IBMI_USER"),
        "password": _require_env("IBMI_PASSWORD"),
    }
    if os.getenv("IBMI_IGNORE_UNAUTHORIZED", "").lower() in {"1", "true", "yes"}:
        creds["ignoreUnauthorized"] = True
    return creds

# Configuration
MAX_RESULT_ROWS = int(os.getenv("MAX_RESULT_ROWS", "500"))
MAX_RESULT_BYTES = int(os.getenv("MAX_RESULT_BYTES", "500000"))
PARALLEL_TIMEOUT = float(os.getenv("PARALLEL_AGENT_TIMEOUT", "120"))
MAX_PARALLEL_AGENTS = int(os.getenv("MAX_PARALLEL_AGENTS", "4"))
ENABLE_AUDIT_LOG = os.getenv("ENABLE_AUDIT_LOG", "1").lower() in {"1", "true", "yes"}

# =============================================================================
# THREAD-SAFE CONNECTION POOL
# =============================================================================

_connection_pool: List[Any] = []
_pool_lock = threading.Lock()
_MAX_POOL_SIZE = int(os.getenv("IBMI_POOL_SIZE", "5"))
_MAX_RETRIES = 3
_RETRY_DELAY_BASE = 2
_active_connections = 0

def _get_pooled_connection_safe() -> Any:
    """Thread-safe connection acquisition with retry logic."""
    global _active_connections
    creds = get_ibmi_credentials()

    for attempt in range(_MAX_RETRIES):
        try:
            # Try to get from pool first (thread-safe)
            with _pool_lock:
                if _connection_pool:
                    return _connection_pool.pop()
                if _active_connections < _MAX_POOL_SIZE:
                    _active_connections += 1

            # Create new connection outside lock
            return connect(creds)
        except Exception as e:
            if attempt == _MAX_RETRIES - 1:
                raise
            delay = _RETRY_DELAY_BASE ** attempt
            time.sleep(delay)

    return connect(creds)

def _return_connection_safe(conn: Any) -> None:
    """Thread-safe connection return to pool."""
    global _active_connections
    with _pool_lock:
        if len(_connection_pool) < _MAX_POOL_SIZE:
            _connection_pool.append(conn)
        else:
            try:
                conn.close()
            except:
                pass
            _active_connections = max(0, _active_connections - 1)

# =============================================================================
# RESULT FORMATTING
# =============================================================================

def format_result(result: Any) -> str:
    """Format results as JSON with size limits."""
    try:
        truncated = False
        if isinstance(result, list) and len(result) > MAX_RESULT_ROWS:
            result = result[:MAX_RESULT_ROWS]
            truncated = True

        output = json.dumps(result, indent=2, default=str)

        if len(output) > MAX_RESULT_BYTES:
            output = output[:MAX_RESULT_BYTES] + "\n... (truncated)"
            truncated = True
        elif truncated:
            output += f"\n... (truncated to {MAX_RESULT_ROWS} rows)"

        return output
    except:
        return str(result)

def run_sql_thread_safe(sql: str, parameters: Optional[QueryParameters] = None) -> str:
    """Execute SQL using thread-safe connection pool."""
    conn = _get_pooled_connection_safe()
    try:
        with conn.execute(sql, parameters=parameters) as cur:
            if getattr(cur, "has_results", False):
                raw = cur.fetchall()
                if isinstance(raw, dict) and "data" in raw:
                    return format_result(raw["data"])
                return format_result(raw)
            return "SQL executed successfully."
    finally:
        _return_connection_safe(conn)

# =============================================================================
# SAFETY & VALIDATION (All security layers preserved)
# =============================================================================

_SAFE_IDENT = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)
_FORBIDDEN_SQL_TOKENS = re.compile(
    r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bMERGE\b|\bDROP\b|\bALTER\b|\bCREATE\b|\bCALL\b|\bGRANT\b|\bREVOKE\b|\bRUN\b|\bCL:\b|\bQCMDEXC\b)",
    re.IGNORECASE,
)

_ALLOWED_SCHEMAS: Set[str] = {"QSYS2", "SYSTOOLS", "SYSIBM", "QSYS", "INFORMATION_SCHEMA"}
user_schemas = os.getenv("ALLOWED_USER_SCHEMAS", "").strip()
if user_schemas:
    _ALLOWED_SCHEMAS.update(s.strip().upper() for s in user_schemas.split(",") if s.strip())
_SYSTEM_SCHEMAS = {"QSYS2", "SYSTOOLS", "SYSIBM", "QSYS", "INFORMATION_SCHEMA"}
_USER_SCHEMAS = _ALLOWED_SCHEMAS - _SYSTEM_SCHEMAS

def _safe_ident(value: str, what: str = "identifier") -> str:
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()

def _safe_ident_or_special(value: str, what: str = "identifier") -> str:
    v = (value or "").strip()
    if not v:
        raise ValueError(f"Invalid {what}: {value!r}")
    if v.startswith("*"):
        if not re.match(r"^\*[A-Z0-9_]+$", v, re.IGNORECASE):
            raise ValueError(f"Invalid {what}: {value!r}")
        return v.upper()
    if not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()

def _safe_schema(value: str) -> str:
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid schema: {value!r}")
    return v.upper()

def _safe_csv_idents(value: str, what: str = "list") -> str:
    parts = [p.strip() for p in (value or "").split(",") if p.strip()]
    if not parts:
        return ""
    return ",".join(_safe_ident(p, what=what) for p in parts)

def _safe_limit(n: int, default: int = 10, max_n: int = 5000) -> int:
    try:
        n = int(n)
    except:
        return default
    return max(1, min(n, max_n))

def _looks_like_safe_select(sql: str) -> None:
    s = (sql or "").strip()
    if not s:
        raise ValueError("Empty SQL not allowed.")
    head = s.lstrip().upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise ValueError("Only SELECT/WITH statements allowed.")
    if ";" in s:
        raise ValueError("Multiple statements not allowed.")
    if _FORBIDDEN_SQL_TOKENS.search(s):
        raise ValueError("Forbidden SQL operation detected.")
    schema_refs = set(re.findall(r"\b([A-Z0-9_#$@]{1,128})\s*\.", s.upper()))
    for sch in schema_refs:
        if sch in {"TABLE", "VALUES", "LATERAL"}:
            continue
        if sch not in _ALLOWED_SCHEMAS:
            raise ValueError(f"Schema '{sch}' not allowed.")

def _validate_simple_clause(clause: str, clause_type: str) -> str:
    if not clause:
        return ""
    clause = clause.strip()
    if not clause:
        return ""
    if "(" in clause or ")" in clause:
        raise ValueError(f"Parentheses not allowed in {clause_type}")
    if re.search(r'\bSELECT\b', clause, re.IGNORECASE):
        raise ValueError(f"SELECT not allowed in {clause_type}")
    if ";" in clause:
        raise ValueError(f"Semicolons not allowed in {clause_type}")
    if _FORBIDDEN_SQL_TOKENS.search(clause):
        raise ValueError(f"Forbidden SQL in {clause_type}")
    return clause

def run_select(sql: str, parameters: Optional[QueryParameters] = None) -> str:
    """Execute safe SELECT with guardrails."""
    try:
        _looks_like_safe_select(sql)
        if ENABLE_AUDIT_LOG:
            print(f"[AUDIT] SQL: {sql[:100]}...", file=sys.stderr)
        return run_sql_thread_safe(sql, parameters=parameters)
    except ValueError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"

# =============================================================================
# SERVICE DISCOVERY & CACHING
# =============================================================================

_services_cache: Dict[Tuple[str, str], bool] = {}
_services_preloaded = False
_views_cache: Dict[Tuple[str, str], bool] = {}

def preload_services() -> int:
    global _services_preloaded, _services_cache
    if _services_preloaded:
        return len(_services_cache)
    try:
        sql = "SELECT SERVICE_SCHEMA_NAME, SERVICE_NAME FROM QSYS2.SERVICES_INFO"
        conn = _get_pooled_connection_safe()
        try:
            with conn.execute(sql) as cur:
                if getattr(cur, "has_results", False):
                    raw = cur.fetchall()
                    rows = raw.get("data", raw) if isinstance(raw, dict) else raw
                    for row in rows:
                        schema = row.get("SERVICE_SCHEMA_NAME", "").upper()
                        name = row.get("SERVICE_NAME", "").upper()
                        if schema and name:
                            _services_cache[(schema, name)] = True
        finally:
            _return_connection_safe(conn)
        _services_preloaded = True
        return len(_services_cache)
    except Exception as e:
        print(f"[SERVICES] Preload failed: {e}", file=sys.stderr)
        return 0

def service_exists(schema: str, service_name: str) -> bool:
    sch = _safe_schema(schema)
    svc = _safe_ident(service_name, what="service_name")
    key = (sch, svc)
    if _services_preloaded:
        return key in _services_cache
    if key in _services_cache:
        return _services_cache[key]
    try:
        sql = "SELECT 1 FROM QSYS2.SERVICES_INFO WHERE SERVICE_SCHEMA_NAME=? AND SERVICE_NAME=? FETCH FIRST 1 ROW ONLY"
        result = run_sql_thread_safe(sql, parameters=[sch, svc])
        ok = "1" in result and "ERROR" not in result
    except:
        ok = False
    _services_cache[key] = ok
    return ok

def view_exists(schema: str, view_name: str) -> bool:
    sch = _safe_schema(schema)
    vw = _safe_ident(view_name, what="view_name")
    key = (sch, vw)
    if key in _views_cache:
        return _views_cache[key]
    try:
        sql = "SELECT 1 FROM QSYS2.SYSTABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=? FETCH FIRST 1 ROW ONLY"
        result = run_sql_thread_safe(sql, parameters=[sch, vw])
        ok = "1" in result and "ERROR" not in result
    except:
        ok = False
    _views_cache[key] = ok
    return ok

# =============================================================================
# SQL TEMPLATES
# =============================================================================

SYSTEM_STATUS_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS(RESET_STATISTICS=>'NO',DETAILED_INFO=>'ALL')) X"
SYSTEM_ACTIVITY_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_ACTIVITY_INFO())"
TOP_CPU_JOBS_SQL = """SELECT JOB_NAME,AUTHORIZATION_NAME AS USER_NAME,SUBSYSTEM,JOB_STATUS,JOB_TYPE,CPU_TIME,TEMPORARY_STORAGE,TOTAL_DISK_IO_COUNT FROM TABLE(QSYS2.ACTIVE_JOB_INFO(SUBSYSTEM_LIST_FILTER=>?,CURRENT_USER_LIST_FILTER=>?,DETAILED_INFO=>'ALL')) X ORDER BY CPU_TIME DESC FETCH FIRST ? ROWS ONLY"""
MSGW_JOBS_SQL = """SELECT JOB_NAME,AUTHORIZATION_NAME AS USER_NAME,SUBSYSTEM,FUNCTION,JOB_STATUS,CPU_TIME,MESSAGE_ID,MESSAGE_TEXT FROM TABLE(QSYS2.ACTIVE_JOB_INFO(DETAILED_INFO=>'ALL')) X WHERE JOB_STATUS='MSGW' ORDER BY SUBSYSTEM,CPU_TIME DESC FETCH FIRST ? ROWS ONLY"""
ASP_INFO_SQL = "SELECT * FROM QSYS2.ASP_INFO ORDER BY ASP_NUMBER"
DISK_HOTSPOTS_SQL = """SELECT ASP_NUMBER,RESOURCE_NAME,SERIAL_NUMBER,HARDWARE_STATUS,RESOURCE_STATUS,PERCENT_USED,UNIT_SPACE_AVAILABLE_GB,TOTAL_READ_REQUESTS,TOTAL_WRITE_REQUESTS FROM QSYS2.SYSDISKSTAT ORDER BY PERCENT_USED DESC FETCH FIRST ? ROWS ONLY"""
NETSTAT_SUMMARY_SQL = """SELECT LOCAL_ADDRESS,LOCAL_PORT,REMOTE_ADDRESS,REMOTE_PORT,IDLE_TIME FROM QSYS2.NETSTAT_INFO ORDER BY IDLE_TIME DESC"""
QSYSOPR_RECENT_MSGS_SQL = """SELECT MSG_TIME,MSGID,MSG_TYPE,SEVERITY,CAST(MSG_TEXT AS VARCHAR(1024)) AS MSG_TEXT,FROM_USER,FROM_JOB,FROM_PGM FROM QSYS2.MESSAGE_QUEUE_INFO WHERE MSGQ_LIB='QSYS' AND MSGQ_NAME='QSYSOPR' ORDER BY MSG_TIME DESC FETCH FIRST ? ROWS ONLY"""
OUTQ_HOTSPOTS_SQL = """SELECT OUTPUT_QUEUE_LIBRARY_NAME AS OUTQ_LIB,OUTPUT_QUEUE_NAME AS OUTQ,NUMBER_OF_FILES,OUTPUT_QUEUE_STATUS,NUMBER_OF_WRITERS FROM QSYS2.OUTPUT_QUEUE_INFO ORDER BY NUMBER_OF_FILES DESC FETCH FIRST ? ROWS ONLY"""
ENDED_JOB_INFO_SQL = """SELECT * FROM TABLE(SYSTOOLS.ENDED_JOB_INFO()) ORDER BY END_TIMESTAMP DESC FETCH FIRST ? ROWS ONLY"""
JOB_QUEUE_ENTRIES_SQL = """SELECT * FROM TABLE(SYSTOOLS.JOB_QUEUE_ENTRIES()) ORDER BY JOB_QUEUE_NAME,JOB_QUEUE_LIBRARY FETCH FIRST ? ROWS ONLY"""
USER_STORAGE_SQL = """SELECT AUTHORIZATION_NAME,STORAGE_USED,TEMPORARY_STORAGE_USED,NUMBER_OF_OBJECTS FROM QSYS2.USER_STORAGE ORDER BY STORAGE_USED DESC FETCH FIRST ? ROWS ONLY"""
PTF_IPL_REQUIRED_SQL = """SELECT PTF_ID,PRODUCT_ID,PRODUCT_OPTION,PTF_STATUS,PTF_ACTION_REQUIRED,LOADED_TIMESTAMP FROM QSYS2.PTF_INFO WHERE PTF_ACTION_REQUIRED='IPL' ORDER BY LOADED_TIMESTAMP DESC FETCH FIRST ? ROWS ONLY"""
SOFTWARE_PRODUCT_INFO_SQL = """SELECT PRODUCT_ID,PRODUCT_OPTION,RELEASE_LEVEL,INSTALLED,LOAD_STATE,TEXT_DESCRIPTION FROM QSYS2.SOFTWARE_PRODUCT_INFO WHERE (? IS NULL OR PRODUCT_ID=?) ORDER BY PRODUCT_ID,PRODUCT_OPTION FETCH FIRST ? ROWS ONLY"""
LICENSE_INFO_SQL = """SELECT * FROM QSYS2.LICENSE_INFO ORDER BY PRODUCT_ID FETCH FIRST ? ROWS ONLY"""
USER_INFO_BASIC_SQL = """SELECT * FROM QSYS2.USER_INFO_BASIC ORDER BY AUTHORIZATION_NAME FETCH FIRST ? ROWS ONLY"""
USER_INFO_PRIVILEGED_SQL = """SELECT AUTHORIZATION_NAME,STATUS,USER_CLASS_NAME,SPECIAL_AUTHORITIES,GROUP_PROFILE_NAME,OWNER,HOME_DIRECTORY,TEXT_DESCRIPTION,PASSWORD_CHANGE_DATE,INVALID_SIGNON_ATTEMPTS FROM QSYS2.USER_INFO ORDER BY AUTHORIZATION_NAME FETCH FIRST ? ROWS ONLY"""
PUBLIC_ALL_OBJECTS_SQL = """SELECT * FROM QSYS2.OBJECT_PRIVILEGES WHERE AUTHORIZATION_NAME='*PUBLIC' AND OBJECT_AUTHORITY='*ALL' ORDER BY SYSTEM_OBJECT_SCHEMA,SYSTEM_OBJECT_NAME,OBJECT_TYPE FETCH FIRST ? ROWS ONLY"""
OBJECT_PRIVILEGES_FOR_OBJECT_SQL = """SELECT * FROM QSYS2.OBJECT_PRIVILEGES WHERE SYSTEM_OBJECT_SCHEMA=? AND SYSTEM_OBJECT_NAME=? ORDER BY AUTHORIZATION_NAME FETCH FIRST ? ROWS ONLY"""
AUTH_LIST_INFO_SQL = """SELECT * FROM QSYS2.AUTHORIZATION_LIST_INFO ORDER BY AUTHORIZATION_LIST_LIBRARY,AUTHORIZATION_LIST_NAME FETCH FIRST ? ROWS ONLY"""
AUTH_LIST_ENTRIES_SQL = """SELECT * FROM QSYS2.AUTHORIZATION_LIST_ENTRIES WHERE AUTHORIZATION_LIST_LIBRARY=? AND AUTHORIZATION_LIST_NAME=? ORDER BY USER_PROFILE_NAME FETCH FIRST ? ROWS ONLY"""
PLAN_CACHE_TOP_SQL = """SELECT * FROM QSYS2.PLAN_CACHE_STATEMENT ORDER BY TOTAL_ELAPSED_TIME DESC FETCH FIRST ? ROWS ONLY"""
PLAN_CACHE_ERRORS_SQL = """SELECT * FROM QSYS2.PLAN_CACHE_STATEMENT WHERE STATEMENT_TEXT IS NOT NULL AND (TOTAL_ERROR_COUNT>0 OR TOTAL_WARNING_COUNT>0) ORDER BY TOTAL_ERROR_COUNT DESC,TOTAL_WARNING_COUNT DESC FETCH FIRST ? ROWS ONLY"""
INDEX_ADVICE_SQL = """SELECT * FROM QSYS2.INDEX_ADVICE ORDER BY ESTIMATED_TIME_SAVINGS DESC FETCH FIRST ? ROWS ONLY"""
LOCK_WAITS_SQL = """SELECT * FROM QSYS2.LOCK_WAITS ORDER BY WAIT_DURATION DESC FETCH FIRST ? ROWS ONLY"""
JOURNAL_INFO_SQL = """SELECT * FROM QSYS2.JOURNAL_INFO ORDER BY JOURNAL_LIBRARY,JOURNAL_NAME FETCH FIRST ? ROWS ONLY"""
JOURNAL_RECEIVER_INFO_SQL = """SELECT * FROM QSYS2.JOURNAL_RECEIVER_INFO ORDER BY JOURNAL_LIBRARY,JOURNAL_NAME,RECEIVER_ATTACH_TIMESTAMP DESC FETCH FIRST ? ROWS ONLY"""
SYSTABLES_IN_SCHEMA_SQL = """SELECT TABLE_SCHEMA,TABLE_NAME,TABLE_TYPE,TABLE_TEXT,LAST_ALTERED_TIMESTAMP FROM QSYS2.SYSTABLES WHERE TABLE_SCHEMA=? ORDER BY TABLE_NAME FETCH FIRST ? ROWS ONLY"""
SYSCOLUMNS_FOR_TABLE_SQL = """SELECT TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME,DATA_TYPE,LENGTH,NUMERIC_SCALE,IS_NULLABLE,COLUMN_TEXT FROM QSYS2.SYSCOLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? ORDER BY ORDINAL_POSITION FETCH FIRST ? ROWS ONLY"""
LARGEST_OBJECTS_SQL = """SELECT OBJLONGSCHEMA AS LIBRARY,OBJNAME AS OBJECT,OBJTYPE,OBJSIZE,LAST_USED_TIMESTAMP FROM TABLE(QSYS2.OBJECT_STATISTICS(?,'*ALL')) X ORDER BY OBJSIZE DESC FETCH FIRST ? ROWS ONLY"""
LIBRARY_SIZES_SQL = """WITH libs(ln) AS (SELECT OBJNAME FROM TABLE(QSYS2.OBJECT_STATISTICS('*ALLSIMPLE','LIB')) AS L) SELECT ln AS LIBRARY,LI.OBJECT_COUNT,LI.LIBRARY_SIZE AS LIBRARY_SIZE_BYTES,ROUND(LI.LIBRARY_SIZE/1e+9,2) AS LIBRARY_SIZE_GB FROM libs,LATERAL(SELECT * FROM TABLE(QSYS2.LIBRARY_INFO(LIBRARY_NAME=>ln,DETAILED_INFO=>'LIBRARY_SIZE'))) LI ORDER BY LI.LIBRARY_SIZE DESC FETCH FIRST ? ROWS ONLY"""
HTTP_GET_VERBOSE_SQL = "SELECT * FROM TABLE(QSYS2.HTTP_GET_VERBOSE(?)) X"
HTTP_POST_VERBOSE_SQL = "SELECT * FROM TABLE(QSYS2.HTTP_POST_VERBOSE(?,?)) X"
SECURITY_INFO_SQL = "SELECT * FROM QSYS2.SECURITY_INFO"
DB_TRANSACTION_INFO_SQL = """SELECT JOB_NAME,AUTHORIZATION_NAME,COMMIT_DEFINITION_NAME,LOCAL_START_TIMESTAMP,STATE,LOCK_SCOPE,LOCK_TIMEOUT FROM QSYS2.DB_TRANSACTION_INFO ORDER BY LOCAL_START_TIMESTAMP DESC FETCH FIRST ? ROWS ONLY"""
ACTIVE_JOBS_DETAILED_SQL = """SELECT JOB_NAME,AUTHORIZATION_NAME AS USER_NAME,SUBSYSTEM,JOB_STATUS,JOB_TYPE,CPU_TIME,ELAPSED_TIME,TEMPORARY_STORAGE,MEMORY_POOL,FUNCTION_TYPE,FUNCTION,SQL_STATEMENT_TEXT FROM TABLE(QSYS2.ACTIVE_JOB_INFO(DETAILED_INFO=>'WORK')) WHERE CPU_TIME>0 ORDER BY CPU_TIME DESC FETCH FIRST ? ROWS ONLY"""
NETSTAT_JOB_INFO_SQL = """SELECT JOB_NAME,AUTHORIZATION_NAME AS USER_NAME,JOB_USER,JOB_NUMBER,CONNECTION_TYPE,LOCAL_ADDRESS,LOCAL_PORT,REMOTE_ADDRESS,REMOTE_PORT,TCP_STATE FROM QSYS2.NETSTAT_JOB_INFO WHERE TCP_STATE='ESTABLISHED' ORDER BY LOCAL_PORT,REMOTE_ADDRESS"""
JOBLOG_INFO_SQL = """SELECT MESSAGE_ID,MESSAGE_TYPE,MESSAGE_TIMESTAMP,FROM_PROGRAM,FROM_MODULE,MESSAGE_SEVERITY,CAST(MESSAGE_TEXT AS VARCHAR(1024)) AS MESSAGE_TEXT FROM TABLE(QSYS2.JOBLOG_INFO(?)) WHERE MESSAGE_SEVERITY>=? ORDER BY MESSAGE_TIMESTAMP DESC FETCH FIRST ? ROWS ONLY"""
SPOOLED_FILE_INFO_SQL = """SELECT JOB_NAME,JOB_USER,JOB_NUMBER,SPOOLED_FILE_NAME,OUTPUT_QUEUE_LIBRARY_NAME,OUTPUT_QUEUE_NAME,STATUS,TOTAL_PAGES,SIZE,CREATE_TIMESTAMP FROM TABLE(QSYS2.SPOOLED_FILE_INFO()) ORDER BY SIZE DESC FETCH FIRST ? ROWS ONLY"""
IFS_OBJECT_STATISTICS_SQL = """SELECT PATH_NAME,OBJECT_TYPE,DATA_SIZE,ALLOCATED_SIZE,OBJECT_OWNER,CREATE_TIMESTAMP,ACCESS_TIMESTAMP,DATA_CHANGE_TIMESTAMP FROM TABLE(QSYS2.IFS_OBJECT_STATISTICS(START_PATH_NAME=>?,SUBTREE_DIRECTORIES=>'YES')) WHERE DATA_SIZE>? ORDER BY DATA_SIZE DESC FETCH FIRST ? ROWS ONLY"""
IFS_OBJECT_LOCK_INFO_SQL = """SELECT PATH_NAME,JOB_NAME,LOCK_TYPE,LOCK_SCOPE,LOCK_STATE FROM TABLE(QSYS2.IFS_OBJECT_LOCK_INFO(?))"""
SYSTEM_VALUE_INFO_SQL = """SELECT SYSTEM_VALUE_NAME,CURRENT_NUMERIC_VALUE,CURRENT_CHARACTER_VALUE,TEXT_DESCRIPTION FROM QSYS2.SYSTEM_VALUE_INFO WHERE (?='*ALL' OR SYSTEM_VALUE_NAME LIKE ?) ORDER BY SYSTEM_VALUE_NAME FETCH FIRST ? ROWS ONLY"""
LIBRARY_LIST_INFO_SQL = """SELECT ORDINAL_POSITION,LIBRARY_NAME,LIBRARY_TYPE,SCHEMA_SIZE FROM QSYS2.LIBRARY_LIST_INFO ORDER BY ORDINAL_POSITION"""
HARDWARE_RESOURCE_INFO_SQL = """SELECT RESOURCE_NAME,RESOURCE_TYPE,RESOURCE_KIND,HARDWARE_STATUS,SYSTEM_RESOURCE_NAME FROM QSYS2.HARDWARE_RESOURCE_INFO ORDER BY RESOURCE_TYPE,RESOURCE_NAME FETCH FIRST ? ROWS ONLY"""
USER_MFA_INFO_SQL = """SELECT AUTHORIZATION_NAME,TOTP_AUTHENTICATION_LEVEL,TOTP_KEY_STATUS,TOTP_KEY_GENERATION_TIMESTAMP FROM QSYS2.USER_INFO WHERE (?='*ALL' OR AUTHORIZATION_NAME=?) FETCH FIRST ? ROWS ONLY"""
CERTIFICATE_INFO_SQL = """SELECT CERTIFICATE_LABEL,CERTIFICATE_STORE,CERTIFICATE_TYPE,CERTIFICATE_STATUS,VALID_FROM,VALID_TO,ISSUER_NAME,SUBJECT_NAME,SERIAL_NUMBER,KEY_SIZE,PUBLIC_KEY_ALGORITHM,SIGNATURE_ALGORITHM FROM QSYS2.CERTIFICATE_INFO WHERE VALID_TO<=CURRENT_TIMESTAMP+? DAYS ORDER BY VALID_TO ASC"""
SUBSYSTEM_POOL_INFO_SQL = """SELECT SUBSYSTEM_DESCRIPTION_LIBRARY,SUBSYSTEM_DESCRIPTION,POOL_ID,POOL_NAME,DEFINED_SIZE,CURRENT_SIZE,ACTIVITY_LEVEL,PAGING_OPTION FROM QSYS2.SUBSYSTEM_POOL_INFO ORDER BY SUBSYSTEM_DESCRIPTION,POOL_ID FETCH FIRST ? ROWS ONLY"""
PROGRAM_SOURCE_INFO_SQL = """SELECT OBJLONGSCHEMA AS LIBRARY,OBJNAME AS PROGRAM,SOURCE_LIBRARY,SOURCE_FILE,SOURCE_MEMBER,OBJCREATED,TEXT_DESCRIPTION FROM TABLE(QSYS2.OBJECT_STATISTICS(?,'*PGM *SRVPGM *MODULE')) WHERE OBJNAME=? AND SOURCE_FILE IS NOT NULL FETCH FIRST ? ROWS ONLY"""
PROGRAM_REFERENCES_SQL = """SELECT FROM_OBJECT_SCHEMA,FROM_OBJECT_NAME,TO_OBJECT_SCHEMA,TO_OBJECT_NAME,REFERENCE_TYPE FROM QSYS2.PROGRAM_REFERENCES WHERE FROM_OBJECT_SCHEMA=? AND FROM_OBJECT_NAME=? FETCH FIRST ? ROWS ONLY"""
SERVICES_SEARCH_SQL = """SELECT SERVICE_CATEGORY,SERVICE_SCHEMA_NAME,SERVICE_NAME,SQL_OBJECT_TYPE,EARLIEST_POSSIBLE_RELEASE FROM QSYS2.SERVICES_INFO WHERE (UPPER(SERVICE_NAME) LIKE UPPER(?) OR UPPER(SERVICE_CATEGORY) LIKE UPPER(?)) ORDER BY SERVICE_CATEGORY,SERVICE_SCHEMA_NAME,SERVICE_NAME FETCH FIRST ? ROWS ONLY"""

# =============================================================================
# CORE FUNCTIONS (Raw callable functions for direct execution)
# =============================================================================

# These are the raw functions that can be called directly.
# They are also wrapped with @tool decorator below for agent usage.

def _get_system_status() -> str:
    return run_select(SYSTEM_STATUS_SQL)

def _get_system_activity() -> str:
    return run_select(SYSTEM_ACTIVITY_SQL)

def _top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    sbs = _safe_csv_idents(subsystem_csv) if subsystem_csv else ""
    usr = _safe_csv_idents(user_csv) if user_csv else ""
    return run_select(TOP_CPU_JOBS_SQL, parameters=[sbs, usr, lim])

def _jobs_in_msgw(limit: int = 50) -> str:
    return run_select(MSGW_JOBS_SQL, parameters=[_safe_limit(limit, 50, 500)])

def _active_jobs_detailed(limit: int = 50) -> str:
    return run_select(ACTIVE_JOBS_DETAILED_SQL, parameters=[_safe_limit(limit, 50, 500)])

def _plan_cache_top(limit: int = 50) -> str:
    return run_select(PLAN_CACHE_TOP_SQL, parameters=[_safe_limit(limit, 50, 5000)])

def _plan_cache_errors(limit: int = 50) -> str:
    return run_select(PLAN_CACHE_ERRORS_SQL, parameters=[_safe_limit(limit, 50, 5000)])

def _index_advice(limit: int = 200) -> str:
    return run_select(INDEX_ADVICE_SQL, parameters=[_safe_limit(limit, 200, 5000)])

def _lock_waits(limit: int = 100) -> str:
    return run_select(LOCK_WAITS_SQL, parameters=[_safe_limit(limit, 100, 5000)])

def _db_transaction_info(limit: int = 100) -> str:
    if not service_exists("QSYS2", "DB_TRANSACTION_INFO"):
        return "ERROR: DB_TRANSACTION_INFO not available. Requires IBM i 7.4+."
    return run_select(DB_TRANSACTION_INFO_SQL, parameters=[_safe_limit(limit, 100, 1000)])

def _subsystem_pool_info(limit: int = 200) -> str:
    if not service_exists("QSYS2", "SUBSYSTEM_POOL_INFO"):
        return "ERROR: SUBSYSTEM_POOL_INFO not available."
    return run_select(SUBSYSTEM_POOL_INFO_SQL, parameters=[_safe_limit(limit, 200, 1000)])

def _list_user_profiles(limit: int = 500) -> str:
    return run_select(USER_INFO_BASIC_SQL, parameters=[_safe_limit(limit, 500, 5000)])

def _list_privileged_profiles(limit: int = 500) -> str:
    return run_select(USER_INFO_PRIVILEGED_SQL, parameters=[_safe_limit(limit, 500, 5000)])

def _public_all_object_authority(limit: int = 200) -> str:
    return run_select(PUBLIC_ALL_OBJECTS_SQL, parameters=[_safe_limit(limit, 200, 5000)])

def _security_info() -> str:
    if not service_exists("QSYS2", "SECURITY_INFO"):
        return "ERROR: SECURITY_INFO not available."
    return run_select(SECURITY_INFO_SQL)

def _user_mfa_settings(user_profile: str = "*ALL", limit: int = 500) -> str:
    lim = _safe_limit(limit, 500, 5000)
    if user_profile.upper() == "*ALL":
        return run_select(USER_MFA_INFO_SQL, parameters=["*ALL", "", lim])
    usr = _safe_ident(user_profile)
    return run_select(USER_MFA_INFO_SQL, parameters=[usr, usr, lim])

def _certificate_info_expiring(days: int = 30, limit: int = 100) -> str:
    if not view_exists("QSYS2", "CERTIFICATE_INFO"):
        return "ERROR: CERTIFICATE_INFO not available."
    return run_select(CERTIFICATE_INFO_SQL, parameters=[max(1, min(days, 365)), _safe_limit(limit, 100, 5000)])

def _user_storage_top(limit: int = 50) -> str:
    return run_select(USER_STORAGE_SQL, parameters=[_safe_limit(limit, 50, 500)])

def _get_asp_info() -> str:
    return run_select(ASP_INFO_SQL)

def _disk_hotspots(limit: int = 10) -> str:
    return run_select(DISK_HOTSPOTS_SQL, parameters=[_safe_limit(limit, 10, 200)])

def _output_queue_hotspots(limit: int = 20) -> str:
    return run_select(OUTQ_HOTSPOTS_SQL, parameters=[_safe_limit(limit, 20, 500)])

def _library_sizes(limit: int = 100) -> str:
    return run_select(LIBRARY_SIZES_SQL, parameters=[_safe_limit(limit, 100, 20000)])

def _spooled_file_info(limit: int = 100) -> str:
    if not service_exists("QSYS2", "SPOOLED_FILE_INFO"):
        return "ERROR: SPOOLED_FILE_INFO not available."
    return run_select(SPOOLED_FILE_INFO_SQL, parameters=[_safe_limit(limit, 100, 1000)])

def _library_list_info() -> str:
    return run_select(LIBRARY_LIST_INFO_SQL)

def _search_sql_services(keyword: str, limit: int = 100) -> str:
    kw = (keyword or "").strip()
    if not kw:
        kw = "%"
    like = f"%{kw}%" if kw != "%" else "%"
    return run_select(SERVICES_SEARCH_SQL, parameters=[like, like, _safe_limit(limit, 100, 5000)])

def _netstat_snapshot() -> str:
    if not view_exists("QSYS2", "NETSTAT_INFO"):
        return "ERROR: NETSTAT_INFO not available."
    return run_select(NETSTAT_SUMMARY_SQL)

def _netstat_job_info() -> str:
    if not view_exists("QSYS2", "NETSTAT_JOB_INFO"):
        return "ERROR: NETSTAT_JOB_INFO not available."
    return run_select(NETSTAT_JOB_INFO_SQL)

def _ptfs_requiring_ipl(limit: int = 200) -> str:
    return run_select(PTF_IPL_REQUIRED_SQL, parameters=[_safe_limit(limit, 200, 2000)])

def _system_values(filter_pattern: str = "*ALL", limit: int = 200) -> str:
    pattern = filter_pattern.strip().upper() if filter_pattern else "*ALL"
    sql_pattern = "%" if pattern == "*ALL" else pattern.replace("*", "%")
    return run_select(SYSTEM_VALUE_INFO_SQL, parameters=[pattern, sql_pattern, _safe_limit(limit, 200, 1000)])

def _qsysopr_messages(limit: int = 50) -> str:
    return run_select(QSYSOPR_RECENT_MSGS_SQL, parameters=[_safe_limit(limit, 50, 500)])

def _ended_jobs(limit: int = 50) -> str:
    return run_select(ENDED_JOB_INFO_SQL, parameters=[_safe_limit(limit, 50, 500)])

def _hardware_resource_info(limit: int = 200) -> str:
    if not service_exists("QSYS2", "HARDWARE_RESOURCE_INFO"):
        return "ERROR: HARDWARE_RESOURCE_INFO not available."
    return run_select(HARDWARE_RESOURCE_INFO_SQL, parameters=[_safe_limit(limit, 200, 1000)])

def _journals(limit: int = 500) -> str:
    return run_select(JOURNAL_INFO_SQL, parameters=[_safe_limit(limit, 500, 5000)])

# =============================================================================
# TOOL DEFINITIONS (Wrapped with @tool for agent usage)
# =============================================================================

# --- PERFORMANCE AGENT TOOLS ---

@tool(name="get-system-status", description="System performance statistics from QSYS2.SYSTEM_STATUS")
def get_system_status() -> str:
    return _get_system_status()

@tool(name="get-system-activity", description="Current IBM i activity metrics")
def get_system_activity() -> str:
    return _get_system_activity()

@tool(name="top-cpu-jobs", description="Top CPU jobs with optional subsystem/user filters")
def top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    return _top_cpu_jobs(limit, subsystem_csv, user_csv)

@tool(name="jobs-in-msgw", description="Jobs in MSGW status")
def jobs_in_msgw(limit: int = 50) -> str:
    return _jobs_in_msgw(limit)

@tool(name="active-jobs-detailed", description="Active jobs with SQL text")
def active_jobs_detailed(limit: int = 50) -> str:
    return _active_jobs_detailed(limit)

@tool(name="plan-cache-top", description="Top SQL by elapsed time")
def plan_cache_top(limit: int = 50) -> str:
    return _plan_cache_top(limit)

@tool(name="plan-cache-errors", description="SQL with errors/warnings")
def plan_cache_errors(limit: int = 50) -> str:
    return _plan_cache_errors(limit)

@tool(name="index-advice", description="Index recommendations")
def index_advice(limit: int = 200) -> str:
    return _index_advice(limit)

@tool(name="lock-waits", description="Lock contention analysis")
def lock_waits(limit: int = 100) -> str:
    return run_select(LOCK_WAITS_SQL, parameters=[_safe_limit(limit, 100, 5000)])

@tool(name="db-transaction-info", description="Active database transactions")
def db_transaction_info(limit: int = 100) -> str:
    if not service_exists("QSYS2", "DB_TRANSACTION_INFO"):
        return "ERROR: DB_TRANSACTION_INFO not available. Requires IBM i 7.4+."
    return run_select(DB_TRANSACTION_INFO_SQL, parameters=[_safe_limit(limit, 100, 1000)])

@tool(name="subsystem-pool-info", description="Memory pool allocations")
def subsystem_pool_info(limit: int = 200) -> str:
    if not service_exists("QSYS2", "SUBSYSTEM_POOL_INFO"):
        return "ERROR: SUBSYSTEM_POOL_INFO not available."
    return run_select(SUBSYSTEM_POOL_INFO_SQL, parameters=[_safe_limit(limit, 200, 1000)])

# --- SECURITY AGENT TOOLS ---

@tool(name="list-user-profiles", description="List IBM i user profiles")
def list_user_profiles(limit: int = 500) -> str:
    return run_select(USER_INFO_BASIC_SQL, parameters=[_safe_limit(limit, 500, 5000)])

@tool(name="list-privileged-profiles", description="Users with special authorities")
def list_privileged_profiles(limit: int = 500) -> str:
    return run_select(USER_INFO_PRIVILEGED_SQL, parameters=[_safe_limit(limit, 500, 5000)])

@tool(name="public-all-object-authority", description="Objects where *PUBLIC has *ALL")
def public_all_object_authority(limit: int = 200) -> str:
    return run_select(PUBLIC_ALL_OBJECTS_SQL, parameters=[_safe_limit(limit, 200, 5000)])

@tool(name="object-privileges", description="Privileges for a specific object")
def object_privileges(schema: str, object_name: str, limit: int = 2000) -> str:
    try:
        return run_select(OBJECT_PRIVILEGES_FOR_OBJECT_SQL, parameters=[
            _safe_schema(schema), _safe_ident(object_name), _safe_limit(limit, 2000, 20000)
        ])
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="authorization-lists", description="List authorization lists")
def authorization_lists(limit: int = 500) -> str:
    return run_select(AUTH_LIST_INFO_SQL, parameters=[_safe_limit(limit, 500, 5000)])

@tool(name="authorization-list-entries", description="Entries in an authorization list")
def authorization_list_entries(auth_list_lib: str, auth_list_name: str, limit: int = 5000) -> str:
    try:
        return run_select(AUTH_LIST_ENTRIES_SQL, parameters=[
            _safe_ident(auth_list_lib), _safe_ident(auth_list_name), _safe_limit(limit, 5000, 50000)
        ])
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="security-info", description="System security configuration")
def security_info() -> str:
    if not service_exists("QSYS2", "SECURITY_INFO"):
        return "ERROR: SECURITY_INFO not available."
    return run_select(SECURITY_INFO_SQL)

@tool(name="user-mfa-settings", description="MFA/TOTP settings for users")
def user_mfa_settings(user_profile: str = "*ALL", limit: int = 500) -> str:
    lim = _safe_limit(limit, 500, 5000)
    if user_profile.upper() == "*ALL":
        return run_select(USER_MFA_INFO_SQL, parameters=["*ALL", "", lim])
    usr = _safe_ident(user_profile)
    return run_select(USER_MFA_INFO_SQL, parameters=[usr, usr, lim])

@tool(name="certificate-info-expiring", description="SSL/TLS certificates expiring soon")
def certificate_info_expiring(days: int = 30, limit: int = 100) -> str:
    if not view_exists("QSYS2", "CERTIFICATE_INFO"):
        return "ERROR: CERTIFICATE_INFO not available."
    return run_select(CERTIFICATE_INFO_SQL, parameters=[max(1, min(days, 365)), _safe_limit(limit, 100, 5000)])

@tool(name="user-storage-top", description="Users consuming the most storage")
def user_storage_top(limit: int = 50) -> str:
    return run_select(USER_STORAGE_SQL, parameters=[_safe_limit(limit, 50, 500)])

# --- STORAGE AGENT TOOLS ---

@tool(name="get-asp-info", description="ASP information")
def get_asp_info() -> str:
    return run_select(ASP_INFO_SQL)

@tool(name="disk-hotspots", description="Disks with highest usage")
def disk_hotspots(limit: int = 10) -> str:
    return run_select(DISK_HOTSPOTS_SQL, parameters=[_safe_limit(limit, 10, 200)])

@tool(name="output-queue-hotspots", description="Output queues with most spooled files")
def output_queue_hotspots(limit: int = 20) -> str:
    return run_select(OUTQ_HOTSPOTS_SQL, parameters=[_safe_limit(limit, 20, 500)])

@tool(name="library-sizes", description="Libraries and their sizes")
def library_sizes(limit: int = 100) -> str:
    return run_select(LIBRARY_SIZES_SQL, parameters=[_safe_limit(limit, 100, 20000)])

@tool(name="largest-objects", description="Largest objects in a library")
def largest_objects(library: str, limit: int = 50) -> str:
    try:
        return run_select(LARGEST_OBJECTS_SQL, parameters=[_safe_ident_or_special(library), _safe_limit(limit, 50, 5000)])
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="ifs-object-stats", description="IFS storage analysis")
def ifs_object_stats(start_path: str = "/", min_size_bytes: int = 1048576, limit: int = 100) -> str:
    if not service_exists("QSYS2", "IFS_OBJECT_STATISTICS"):
        return "ERROR: IFS_OBJECT_STATISTICS not available."
    return run_select(IFS_OBJECT_STATISTICS_SQL, parameters=[start_path, max(0, min_size_bytes), _safe_limit(limit, 100, 1000)])

@tool(name="ifs-object-locks", description="Jobs holding locks on IFS object")
def ifs_object_locks(path_name: str) -> str:
    if not service_exists("QSYS2", "IFS_OBJECT_LOCK_INFO"):
        return "ERROR: IFS_OBJECT_LOCK_INFO not available."
    return run_select(IFS_OBJECT_LOCK_INFO_SQL, parameters=[path_name.strip()])

@tool(name="spooled-file-info", description="Spooled files on the system")
def spooled_file_info(limit: int = 100) -> str:
    if not service_exists("QSYS2", "SPOOLED_FILE_INFO"):
        return "ERROR: SPOOLED_FILE_INFO not available."
    return run_select(SPOOLED_FILE_INFO_SQL, parameters=[_safe_limit(limit, 100, 1000)])

# --- DEVELOPER AGENT TOOLS ---

@tool(name="list-tables-in-schema", description="List tables/views in a schema")
def list_tables_in_schema(schema: str, limit: int = 5000) -> str:
    try:
        return run_select(SYSTABLES_IN_SCHEMA_SQL, parameters=[_safe_schema(schema), _safe_limit(limit, 5000, 50000)])
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="describe-table", description="Describe a table's columns")
def describe_table(schema: str, table: str, limit: int = 5000) -> str:
    try:
        return run_select(SYSCOLUMNS_FOR_TABLE_SQL, parameters=[
            _safe_schema(schema), _safe_ident(table), _safe_limit(limit, 5000, 50000)
        ])
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="get-program-source-info", description="Find source location for a program")
def get_program_source_info(library: str, program: str, limit: int = 10) -> str:
    try:
        return run_select(PROGRAM_SOURCE_INFO_SQL, parameters=[
            _safe_ident_or_special(library), _safe_ident(program), _safe_limit(limit, 10, 100)
        ])
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="read-source-member", description="Read source code from a member")
def read_source_member(library: str, source_file: str, member: str, limit: int = 1000) -> str:
    try:
        lib = _safe_schema(library)
        srcf = _safe_ident(source_file)
        mbr = _safe_ident(member)
        lim = _safe_limit(limit, 1000, 10000)
        sql = f"SELECT SRCSEQ,SRCDAT,SRCDTA FROM {lib}.{srcf} ORDER BY SRCSEQ FETCH FIRST {lim} ROWS ONLY"
        return run_select(sql)
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="analyze-program-dependencies", description="Objects referenced by a program")
def analyze_program_dependencies(library: str, program: str, limit: int = 500) -> str:
    if not service_exists("QSYS2", "PROGRAM_REFERENCES"):
        return "ERROR: PROGRAM_REFERENCES not available."
    try:
        return run_select(PROGRAM_REFERENCES_SQL, parameters=[
            _safe_ident(library), _safe_ident(program), _safe_limit(limit, 500, 5000)
        ])
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="search-sql-services", description="Search IBM i SQL services catalog")
def search_sql_services(keyword: str, limit: int = 100) -> str:
    kw = (keyword or "").strip()
    if not kw:
        return "ERROR: keyword required"
    like = f"%{kw}%"
    return run_select(SERVICES_SEARCH_SQL, parameters=[like, like, _safe_limit(limit, 100, 5000)])

@tool(name="query-user-table", description="Query business data from user tables")
def query_user_table(schema: str, table: str, where_clause: str = "", order_by: str = "", limit: int = 100) -> str:
    try:
        sch = _safe_schema(schema)
        tbl = _safe_ident(table)
        lim = _safe_limit(limit, 100, 5000)
        if sch not in _ALLOWED_SCHEMAS:
            return f"ERROR: Schema {sch} not allowed."
        where_clause = _validate_simple_clause(where_clause, "WHERE")
        order_by = _validate_simple_clause(order_by, "ORDER BY")
        sql = f"SELECT * FROM {sch}.{tbl}"
        if where_clause:
            sql += f" WHERE {where_clause}"
        if order_by:
            sql += f" ORDER BY {order_by}"
        sql += f" FETCH FIRST {lim} ROWS ONLY"
        return run_select(sql)
    except ValueError as e:
        return f"ERROR: {e}"

@tool(name="library-list-info", description="Current job's library list")
def library_list_info() -> str:
    return run_select(LIBRARY_LIST_INFO_SQL)

# --- NETWORK AGENT TOOLS ---

@tool(name="netstat-snapshot", description="Network connections snapshot")
def netstat_snapshot() -> str:
    if not view_exists("QSYS2", "NETSTAT_INFO"):
        return "ERROR: NETSTAT_INFO not available."
    return run_select(NETSTAT_SUMMARY_SQL)

@tool(name="netstat-job-info", description="Network connections with owning jobs")
def netstat_job_info() -> str:
    if not view_exists("QSYS2", "NETSTAT_JOB_INFO"):
        return "ERROR: NETSTAT_JOB_INFO not available."
    return run_select(NETSTAT_JOB_INFO_SQL)

@tool(name="http-get-verbose", description="HTTP GET request")
def http_get_verbose(url: str) -> str:
    if not service_exists("QSYS2", "HTTP_GET_VERBOSE"):
        return "ERROR: HTTP_GET_VERBOSE not available."
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return "ERROR: URL must start with http:// or https://"
    return run_select(HTTP_GET_VERBOSE_SQL, parameters=[url])

@tool(name="http-post-verbose", description="HTTP POST request")
def http_post_verbose(url: str, body: str) -> str:
    if not service_exists("QSYS2", "HTTP_POST_VERBOSE"):
        return "ERROR: HTTP_POST_VERBOSE not available."
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return "ERROR: URL must start with http:// or https://"
    return run_select(HTTP_POST_VERBOSE_SQL, parameters=[url, body or ""])

@tool(name="joblog-info", description="Job log messages for a specific job")
def joblog_info(job_name: str, min_severity: int = 20, limit: int = 100) -> str:
    if not service_exists("QSYS2", "JOBLOG_INFO"):
        return "ERROR: JOBLOG_INFO not available."
    job = job_name.strip() if job_name else "*"
    return run_select(JOBLOG_INFO_SQL, parameters=[job, max(0, min(99, min_severity)), _safe_limit(limit, 100, 1000)])

# --- DIAGNOSTICS AGENT TOOLS ---

@tool(name="ptfs-requiring-ipl", description="PTFs that require IPL")
def ptfs_requiring_ipl(limit: int = 200) -> str:
    return run_select(PTF_IPL_REQUIRED_SQL, parameters=[_safe_limit(limit, 200, 2000)])

@tool(name="software-products", description="Installed licensed products")
def software_products(product_id: str = "", limit: int = 500) -> str:
    pid = _safe_ident(product_id) if product_id else None
    return run_select(SOFTWARE_PRODUCT_INFO_SQL, parameters=[pid, pid, _safe_limit(limit, 500, 5000)])

@tool(name="license-info", description="License information")
def license_info(limit: int = 200) -> str:
    return run_select(LICENSE_INFO_SQL, parameters=[_safe_limit(limit, 200, 5000)])

@tool(name="journals", description="Journal configuration")
def journals(limit: int = 500) -> str:
    return run_select(JOURNAL_INFO_SQL, parameters=[_safe_limit(limit, 500, 5000)])

@tool(name="journal-receivers", description="Journal receivers status")
def journal_receivers(limit: int = 500) -> str:
    return run_select(JOURNAL_RECEIVER_INFO_SQL, parameters=[_safe_limit(limit, 500, 5000)])

@tool(name="system-values", description="System values information")
def system_values(filter_pattern: str = "*ALL", limit: int = 200) -> str:
    pattern = filter_pattern.strip().upper() if filter_pattern else "*ALL"
    sql_pattern = "%" if pattern == "*ALL" else pattern.replace("*", "%")
    return run_select(SYSTEM_VALUE_INFO_SQL, parameters=[pattern, sql_pattern, _safe_limit(limit, 200, 1000)])

@tool(name="hardware-resource-info", description="Hardware configuration")
def hardware_resource_info(limit: int = 200) -> str:
    if not service_exists("QSYS2", "HARDWARE_RESOURCE_INFO"):
        return "ERROR: HARDWARE_RESOURCE_INFO not available."
    return run_select(HARDWARE_RESOURCE_INFO_SQL, parameters=[_safe_limit(limit, 200, 1000)])

@tool(name="ended-jobs", description="Recently ended jobs")
def ended_jobs(limit: int = 50) -> str:
    return run_select(ENDED_JOB_INFO_SQL, parameters=[_safe_limit(limit, 50, 500)])

@tool(name="job-queue-entries", description="Job queue entries")
def job_queue_entries(limit: int = 200) -> str:
    return run_select(JOB_QUEUE_ENTRIES_SQL, parameters=[_safe_limit(limit, 200, 2000)])

@tool(name="qsysopr-messages", description="Recent QSYSOPR messages")
def qsysopr_messages(limit: int = 50) -> str:
    return run_select(QSYSOPR_RECENT_MSGS_SQL, parameters=[_safe_limit(limit, 50, 500)])

# =============================================================================
# TOOL CATALOG v3.0 - Semantic Tool Descriptions for LLM Selection
# =============================================================================

# AVAILABLE_TOOLS provides semantic descriptions for LLM to understand each tool's purpose
# Format: tool_name -> {description, use_when, function, status_msg, requires_params}
AVAILABLE_TOOLS = {
    # System Performance Tools
    "get-system-status": {
        "description": "Get overall system performance metrics including CPU utilization, memory usage, disk I/O, and active job counts",
        "use_when": ["system performance", "CPU usage", "memory usage", "system health", "overall status"],
        "function": _get_system_status,
        "status_msg": "Checking system status"
    },
    "get-system-activity": {
        "description": "Get current real-time system activity metrics",
        "use_when": ["current activity", "real-time metrics", "what's happening now"],
        "function": _get_system_activity,
        "status_msg": "Getting system activity"
    },
    "top-cpu-jobs": {
        "description": "Find jobs consuming the most CPU resources",
        "use_when": ["slow system", "high CPU", "CPU hogs", "resource consumers", "what's using CPU"],
        "function": lambda: _top_cpu_jobs(20),
        "status_msg": "Finding top CPU consumers"
    },
    "jobs-in-msgw": {
        "description": "Find jobs stuck in MSGW (message wait) status requiring operator intervention",
        "use_when": ["stuck jobs", "MSGW", "message wait", "jobs needing attention", "hung jobs"],
        "function": lambda: _jobs_in_msgw(30),
        "status_msg": "Looking for stuck jobs"
    },
    "active-jobs-detailed": {
        "description": "Get detailed information about active jobs including SQL statements being executed",
        "use_when": ["active jobs", "running jobs", "what jobs are running", "job details"],
        "function": lambda: _active_jobs_detailed(50),
        "status_msg": "Analyzing active jobs"
    },
    "lock-waits": {
        "description": "Analyze lock contention showing jobs waiting for locks and what's holding them",
        "use_when": ["lock contention", "deadlock", "waiting for locks", "blocking", "contention"],
        "function": lambda: _lock_waits(50),
        "status_msg": "Checking lock contention"
    },
    "plan-cache-top": {
        "description": "Find slowest SQL queries by elapsed time from the plan cache",
        "use_when": ["slow SQL", "query performance", "SQL tuning", "slow queries", "database performance"],
        "function": lambda: _plan_cache_top(30),
        "status_msg": "Examining slow SQL queries"
    },
    "plan-cache-errors": {
        "description": "Find SQL statements with errors or warnings in the plan cache",
        "use_when": ["SQL errors", "query errors", "SQL warnings", "failed queries"],
        "function": lambda: _plan_cache_errors(30),
        "status_msg": "Finding SQL errors"
    },
    "index-advice": {
        "description": "Get index recommendations from the Db2 optimizer",
        "use_when": ["index recommendations", "missing indexes", "SQL optimization", "create index"],
        "function": lambda: _index_advice(30),
        "status_msg": "Checking index recommendations"
    },

    # Security Tools
    "list-user-profiles": {
        "description": "List all IBM i user profiles with basic information",
        "use_when": ["list users", "all users", "user profiles", "who has access"],
        "function": lambda: _list_user_profiles(200),
        "status_msg": "Listing user profiles"
    },
    "list-privileged-profiles": {
        "description": "Find users with special authorities (*ALLOBJ, *SECADM, etc.)",
        "use_when": ["privileged users", "admin users", "special authorities", "who has admin"],
        "function": lambda: _list_privileged_profiles(100),
        "status_msg": "Finding privileged users"
    },
    "public-all-object-authority": {
        "description": "Find objects where *PUBLIC has *ALL authority (security exposure)",
        "use_when": ["public authority", "security exposure", "*PUBLIC access", "authority audit"],
        "function": lambda: _public_all_object_authority(100),
        "status_msg": "Checking *PUBLIC exposure"
    },
    "security-info": {
        "description": "Get system security configuration and settings",
        "use_when": ["security settings", "security configuration", "QSECURITY", "security level"],
        "function": _security_info,
        "status_msg": "Reviewing security settings"
    },
    "user-mfa-settings": {
        "description": "Check MFA/TOTP configuration for user profiles",
        "use_when": ["MFA", "TOTP", "two-factor", "multi-factor authentication"],
        "function": lambda: _user_mfa_settings("*ALL", 100),
        "status_msg": "Checking MFA configuration"
    },
    "certificate-info-expiring": {
        "description": "Find SSL/TLS certificates expiring within specified days",
        "use_when": ["SSL certificates", "TLS certificates", "expiring certs", "certificate management"],
        "function": lambda: _certificate_info_expiring(60),
        "status_msg": "Finding expiring certificates"
    },
    "user-storage-top": {
        "description": "Find users consuming the most storage",
        "use_when": ["user storage", "storage by user", "who's using space"],
        "function": lambda: _user_storage_top(50),
        "status_msg": "Analyzing user storage"
    },

    # Storage Tools
    "get-asp-info": {
        "description": "Get ASP (Auxiliary Storage Pool) disk utilization and capacity",
        "use_when": ["disk usage", "ASP", "disk capacity", "storage pools", "how much disk"],
        "function": _get_asp_info,
        "status_msg": "Checking disk utilization"
    },
    "disk-hotspots": {
        "description": "Find disk units with highest utilization",
        "use_when": ["disk hotspots", "busy disks", "disk I/O", "storage bottleneck"],
        "function": lambda: _disk_hotspots(10),
        "status_msg": "Finding disk hotspots"
    },
    "library-sizes": {
        "description": "Get library sizes sorted by largest",
        "use_when": ["library sizes", "biggest libraries", "library storage", "which libraries are large"],
        "function": lambda: _library_sizes(50),
        "status_msg": "Calculating library sizes"
    },
    "output-queue-hotspots": {
        "description": "Find output queues with most spooled files",
        "use_when": ["spool files", "output queues", "print queues", "spooled file backlog"],
        "function": lambda: _output_queue_hotspots(20),
        "status_msg": "Checking spool queues"
    },
    "spooled-file-info": {
        "description": "Get information about spooled files on the system",
        "use_when": ["spooled files", "print files", "spool status"],
        "function": lambda: _spooled_file_info(50),
        "status_msg": "Analyzing spooled files"
    },

    # Developer/Metadata Tools
    "library-list-info": {
        "description": "Get current job's library list",
        "use_when": ["library list", "LIBL", "current libraries"],
        "function": _library_list_info,
        "status_msg": "Getting library list"
    },
    "search-sql-services": {
        "description": "Search IBM i SQL services catalog for available services",
        "use_when": ["find service", "SQL services", "available services", "QSYS2 services"],
        "function": lambda: _search_sql_services("", 100),
        "status_msg": "Searching SQL services"
    },

    # Network Tools
    "netstat-snapshot": {
        "description": "Get network connections snapshot",
        "use_when": ["network connections", "netstat", "TCP connections", "who's connected"],
        "function": _netstat_snapshot,
        "status_msg": "Checking network connections"
    },
    "netstat-job-info": {
        "description": "Get network connections with owning job information",
        "use_when": ["network by job", "connections to jobs", "which job owns connection"],
        "function": _netstat_job_info,
        "status_msg": "Mapping connections to jobs"
    },

    # Diagnostics Tools
    "ptfs-requiring-ipl": {
        "description": "Find PTFs that require an IPL to apply",
        "use_when": ["PTFs", "patches", "IPL required", "pending PTFs"],
        "function": lambda: _ptfs_requiring_ipl(50),
        "status_msg": "Checking PTFs requiring IPL"
    },
    "system-values": {
        "description": "Get system values configuration",
        "use_when": ["system values", "SYSVAL", "system configuration"],
        "function": lambda: _system_values("*ALL", 100),
        "status_msg": "Reading system values"
    },
    "qsysopr-messages": {
        "description": "Get recent QSYSOPR operator messages",
        "use_when": ["operator messages", "QSYSOPR", "system messages", "alerts"],
        "function": lambda: _qsysopr_messages(30),
        "status_msg": "Reading operator messages"
    },
    "ended-jobs": {
        "description": "Get information about recently ended jobs",
        "use_when": ["ended jobs", "completed jobs", "job history", "what jobs ended"],
        "function": lambda: _ended_jobs(30),
        "status_msg": "Checking ended jobs"
    },
    "hardware-resource-info": {
        "description": "Get hardware configuration and status",
        "use_when": ["hardware", "hardware status", "system hardware", "resources"],
        "function": lambda: _hardware_resource_info(50),
        "status_msg": "Reviewing hardware status"
    },
    "journals": {
        "description": "Get journal configuration",
        "use_when": ["journals", "journaling", "journal receivers", "HA configuration"],
        "function": lambda: _journals(50),
        "status_msg": "Checking journal configuration"
    },
}

# =============================================================================
# LLM TOOL SELECTOR v3.0 - Replaces Keyword Matching
# =============================================================================

TOOL_SELECTION_PROMPT = """You are an IBM i expert. Given a user query, select which tools to run.

AVAILABLE TOOLS:
{tool_catalog}

USER QUERY: {query}

INSTRUCTIONS:
1. Select ONLY tools that directly help answer the query
2. Keep selection minimal - don't run unnecessary tools
3. If the query is about listing objects/programs in a library, set needs_dynamic_sql=true
4. If the query is about configuration (like "which libraries can you access"), it may not need tools

Respond with ONLY valid JSON (no markdown):
{{
  "selected_tools": ["tool-name-1", "tool-name-2"],
  "needs_dynamic_sql": false,
  "dynamic_sql_intent": null,
  "reasoning": "Brief explanation of selection"
}}

SPECIAL CASES:
- "list programs/objects in LIBRARY" → needs_dynamic_sql=true, dynamic_sql_intent="List objects in specific library"
- "which libraries can you access" → selected_tools=[], return config info
- "why is system slow" → select performance + storage tools
- "health check" → select multiple diagnostic tools"""

def _format_tool_catalog() -> str:
    """Format AVAILABLE_TOOLS catalog for LLM consumption."""
    lines = []
    for name, info in AVAILABLE_TOOLS.items():
        lines.append(f"- {name}: {info['description']}")
    return "\n".join(lines)

def _quick_llm_call(prompt: str) -> str:
    """Make a quick LLM call for tool selection (uses faster model if available)."""
    try:
        model_id = os.getenv("OPENROUTER_MODEL_ID", "google/gemini-2.0-flash-001")
        from openai import OpenAI

        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPENROUTER_API_KEY")
        )

        response = client.chat.completions.create(
            model=model_id,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.1  # Low temperature for consistent selection
        )

        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[DEBUG] LLM call failed: {e}", file=sys.stderr)
        return '{"selected_tools": [], "needs_dynamic_sql": true, "dynamic_sql_intent": "fallback", "reasoning": "LLM call failed"}'

def select_tools_with_llm(query: str) -> dict:
    """Use LLM to intelligently select tools based on user intent.

    Returns dict with:
        - selected_tools: list of tool names to execute
        - needs_dynamic_sql: bool - whether to generate custom SQL
        - dynamic_sql_intent: str - what the dynamic SQL should do
        - reasoning: str - why these tools were selected
    """
    catalog = _format_tool_catalog()
    prompt = TOOL_SELECTION_PROMPT.format(tool_catalog=catalog, query=query)

    response = _quick_llm_call(prompt)

    # Parse JSON response
    try:
        # Clean up response (remove markdown code blocks if present)
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        response = response.strip()

        result = json.loads(response)

        # Validate response structure
        if "selected_tools" not in result:
            result["selected_tools"] = []
        if "needs_dynamic_sql" not in result:
            result["needs_dynamic_sql"] = False
        if "dynamic_sql_intent" not in result:
            result["dynamic_sql_intent"] = None

        return result
    except json.JSONDecodeError as e:
        print(f"[DEBUG] Failed to parse LLM response: {e}", file=sys.stderr)
        print(f"[DEBUG] Response was: {response[:200]}", file=sys.stderr)
        # Fallback: try dynamic SQL
        return {
            "selected_tools": [],
            "needs_dynamic_sql": True,
            "dynamic_sql_intent": query,
            "reasoning": "Failed to parse tool selection, falling back to dynamic SQL"
        }

# =============================================================================
# DYNAMIC SQL GENERATOR v3.0 - LLM Generates Custom Queries
# =============================================================================

MAX_SQL_ATTEMPTS = 5

DYNAMIC_SQL_PROMPT = """You are an IBM i SQL expert. Generate a safe, read-only SQL query.

USER'S REQUEST: {query}
{previous_context}

AVAILABLE SCHEMAS: QSYS2, SYSTOOLS, SYSIBM, QSYS{user_schemas}

IMPORTANT RULES:
1. ONLY SELECT statements - no INSERT/UPDATE/DELETE/DROP/CREATE/CALL
2. Use QSYS2 catalog views for system queries
3. Always include FETCH FIRST n ROWS ONLY (max 500)
4. NO semicolons at end
5. NO SQL comments

COMMON PATTERNS:
- List programs in library: SELECT * FROM TABLE(QSYS2.OBJECT_STATISTICS('LIBNAME', '*PGM')) X FETCH FIRST 100 ROWS ONLY
- List all objects in library: SELECT * FROM TABLE(QSYS2.OBJECT_STATISTICS('LIBNAME', '*ALL')) X FETCH FIRST 200 ROWS ONLY
- Library info: SELECT * FROM TABLE(QSYS2.LIBRARY_INFO('LIBNAME'))
- Tables in schema: SELECT * FROM QSYS2.SYSTABLES WHERE TABLE_SCHEMA='SCHEMANAME' FETCH FIRST 200 ROWS ONLY
- User info: SELECT * FROM QSYS2.USER_INFO WHERE AUTHORIZATION_NAME='USERNAME'

Respond with ONLY valid JSON (no markdown):
{{
  "sql": "SELECT ...",
  "explanation": "What this query does"
}}"""

def generate_dynamic_sql(query: str, attempt: int = 1, previous_sql: str = "", error: str = "") -> dict:
    """Generate custom SQL using LLM with retry logic.

    Args:
        query: User's request
        attempt: Current attempt number (1-5)
        previous_sql: SQL from previous attempt if retrying
        error: Error message from previous attempt

    Returns:
        dict with 'sql' and 'explanation', or 'error' if failed
    """
    if attempt > MAX_SQL_ATTEMPTS:
        return {"error": f"Unable to generate valid SQL after {MAX_SQL_ATTEMPTS} attempts"}

    # Build context for retry
    previous_context = ""
    if previous_sql and error:
        previous_context = f"\nPREVIOUS ATTEMPT (failed):\nSQL: {previous_sql}\nERROR: {error}\n\nPlease fix the issue and try again."

    # Add user schemas if configured
    user_schema_str = ""
    if _USER_SCHEMAS:
        user_schema_str = ", " + ", ".join(_USER_SCHEMAS)

    prompt = DYNAMIC_SQL_PROMPT.format(
        query=query,
        previous_context=previous_context,
        user_schemas=user_schema_str
    )

    response = _quick_llm_call(prompt)

    try:
        # Clean up response
        response = response.strip()
        if response.startswith("```"):
            response = response.split("```")[1]
            if response.startswith("json"):
                response = response[4:]
        response = response.strip()

        result = json.loads(response)

        if "sql" not in result:
            return generate_dynamic_sql(query, attempt + 1, "", "No SQL in response")

        # Validate the SQL before returning
        try:
            _looks_like_safe_select(result["sql"])
            return result
        except ValueError as e:
            # SQL validation failed, retry
            return generate_dynamic_sql(query, attempt + 1, result["sql"], str(e))

    except json.JSONDecodeError as e:
        return generate_dynamic_sql(query, attempt + 1, "", f"JSON parse error: {e}")

# =============================================================================
# PARALLEL TOOL EXECUTOR v2.0 - Direct Tool Execution with Streaming UI
# =============================================================================

@dataclass
class ToolResult:
    """Result from a single tool execution."""
    name: str
    status_msg: str
    status: str  # "pending", "running", "success", "error"
    result: str
    elapsed: float = 0.0
    error: Optional[str] = None

class ParallelToolExecutor:
    """Execute tools directly in parallel with real-time streaming UI."""

    def __init__(self):
        self._status: Dict[str, ToolResult] = {}
        # Keep deterministic display order for the status table (per query)
        self._status_order: List[str] = []
        self._lock = threading.Lock()
        self._start_time: float = 0.0

    def _update_status(self, name: str, status_msg: str, status: str, elapsed: float = 0.0, error: str = None):
        """Thread-safe status update."""
        with self._lock:
            self._status[name] = ToolResult(
                name=name,
                status_msg=status_msg,
                status=status,
                result="",
                elapsed=elapsed,
                error=error
            )

    def _build_status_table(self) -> Table:
        """Build Rich table showing real-time tool execution status."""
        table = Table(
            title="[bold cyan]Gathering System Data...[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            show_header=True,
            header_style="bold white"
        )
        table.add_column("Check", style="white", width=40)
        table.add_column("Status", style="white", width=12, justify="center")
        table.add_column("Time", style="dim", width=8, justify="right")

        with self._lock:
            # Deterministic row ordering: show the current query tools in selection order.
            # Fallback: include any unexpected keys (shouldn't happen) at the end.
            ordered_names = list(self._status_order)
            for extra_name in self._status.keys():
                if extra_name not in self._status_order:
                    ordered_names.append(extra_name)

            for name in ordered_names:
                result = self._status.get(name)
                if result is None:
                    continue
                # Status icons
                icons = {"pending": "○", "running": "◐", "success": "●", "error": "✗", "timeout": "⏱"}
                icon = icons.get(result.status, "○")

                # Status colors
                status_style = {
                    "pending": "dim",
                    "running": "yellow",
                    "success": "green",
                    "error": "red",
                    "timeout": "red",
                }.get(result.status, "white")

                # Time display
                time_str = f"{result.elapsed:.1f}s" if result.elapsed > 0 else "-"

                # Status text - show error message if available
                if result.status == "error" and result.error:
                    status_text = result.error[:20] + "..." if len(result.error) > 20 else result.error
                else:
                    status_text = {
                        "pending": "Pending",
                        "running": "Running",
                        "success": "Done",
                        "error": "Error"
                    }.get(result.status, result.status)

                table.add_row(
                    f"{icon} {result.status_msg}",
                    f"[{status_style}]{status_text}[/{status_style}]",
                    time_str
                )

        return table

    def execute_tools_parallel(self, tools: List[Tuple[str, callable, str]]) -> Dict[str, str]:
        """Execute all tools in parallel with streaming UI updates.

        Args:
            tools: List of (tool_name, function, status_message) tuples

        Returns:
            Dict mapping tool_name to result string
        """
        self._start_time = time.time()
        results: Dict[str, str] = {}

        # IMPORTANT: Reset per-query status state.
        # Without this, rows from previous queries persist in the Rich table.
        with self._lock:
            self._status.clear()
            self._status_order = []

        # Initialize all tools as pending
        for name, func, status_msg in tools:
            self._status_order.append(name)
            self._update_status(name, status_msg, "pending")

        def run_single_tool(tool_info: Tuple[str, callable, str]) -> Tuple[str, str]:
            """Execute a single tool and return (name, result)."""
            name, func, status_msg = tool_info
            start = time.time()
            self._update_status(name, status_msg, "running")

            try:
                # Call the tool function
                result = func()
                elapsed = time.time() - start
                self._update_status(name, status_msg, "success", elapsed)
                return name, result
            except Exception as e:
                elapsed = time.time() - start
                error_type = type(e).__name__
                error_detail = str(e)[:100] if str(e) else "Unknown error"
                error_msg = f"ERROR: {error_type}: {error_detail}"
                self._update_status(name, status_msg, "error", elapsed, f"{error_type}: {error_detail[:30]}")
                # Print to stderr for debugging
                print(f"[DEBUG] Tool '{name}' failed: {error_type}: {error_detail}", file=sys.stderr)
                return name, error_msg

        max_workers = max(1, min(MAX_PARALLEL_AGENTS, len(tools)))

        # Execute with Rich Live display for streaming updates
        if _has_rich and _console:
            with Live(self._build_status_table(), console=_console, refresh_per_second=4, transient=False) as live:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [executor.submit(run_single_tool, t) for t in tools]

                    try:
                        for future in as_completed(futures, timeout=PARALLEL_TIMEOUT):
                            try:
                                name, result = future.result()
                                results[name] = result
                            except Exception:
                                # Errors are already captured in run_single_tool and status updated.
                                pass
                            live.update(self._build_status_table())
                    except TimeoutError:
                        # Mark unfinished tasks as timed out
                        for idx, future in enumerate(futures):
                            if not future.done():
                                # Best-effort cancel (may fail if already running)
                                try:
                                    future.cancel()
                                except Exception:
                                    pass
                                tool_name = tools[idx][0]
                                self._update_status(tool_name, tools[idx][2], "timeout", time.time() - self._start_time, "Timeout")
                        live.update(self._build_status_table())

                # Final update
                live.update(self._build_status_table())
        else:
            # Fallback without Rich
            print("\nGathering system data...")
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(run_single_tool, t) for t in tools]

                try:
                    for future in as_completed(futures, timeout=PARALLEL_TIMEOUT):
                        try:
                            name, result = future.result()
                            results[name] = result
                            print(f"  ✓ {name}")
                        except Exception as e:
                            print(f"  ✗ Error: {e}")
                except TimeoutError:
                    # Mark unfinished tools as timed out (stdout-only mode)
                    for idx, future in enumerate(futures):
                        if not future.done():
                            tool_name = tools[idx][0]
                            print(f"  ⏱ Timeout: {tool_name}")

        return results

# =============================================================================
# RESULT SYNTHESIZER v3.0 - Enhanced Output Formatting
# =============================================================================

SYNTHESIS_INSTRUCTIONS_V3 = """You are an expert IBM i analyst providing clear, actionable reports.

FORMATTING RULES:
1. Start with a 1-2 sentence executive summary
2. Use headers (##) to organize sections
3. Use bullet points for lists
4. Highlight key metrics with **bold**
5. Use markdown tables for comparing multiple items (programs, jobs, users, etc.)
6. End with prioritized recommendations (numbered list)
7. Keep response concise - no filler text
8. NEVER mention "data source", "tool", or "query" - present as direct observations
9. If data is empty or shows no results, say so clearly

TABLE FORMAT EXAMPLE:
| Name | Type | Size | Description |
|------|------|------|-------------|
| ORDENT | RPGLE | 45KB | Order Entry |

GOOD EXAMPLE:
## Summary
Found 23 programs in MKLIB library, predominantly RPG applications.

## Program Inventory
| Program | Type | Size | Created |
|---------|------|------|---------|
| ORDENT | RPGLE | 45KB | 2024-01-15 |

## Recommendations
1. **Review ORDENT** - largest program at 45KB
2. Archive unused programs older than 1 year

BAD EXAMPLE (don't do this):
"The data shows that according to the query results, the first data source returned..."
"""

def synthesize_results_v3(query: str, tool_results: Dict[str, str]) -> str:
    """Use ONE LLM call to synthesize all tool results into a unified response.

    Enhanced v3.0 with prettier formatting (tables, better structure).

    Args:
        query: The user's original question
        tool_results: Dict mapping tool names to their raw results

    Returns:
        Synthesized analysis as markdown string
    """
    # Format the raw data for the LLM (without exposing tool names)
    data_sections = []
    for i, (name, result) in enumerate(tool_results.items(), 1):
        # Skip error results or empty results
        if result and not result.startswith("ERROR"):
            # Truncate very large results
            if len(result) > 15000:
                result = result[:15000] + "\n... (truncated)"
            data_sections.append(f"=== Data {i} ===\n{result}")

    if not data_sections:
        return "Unable to gather system data. Please check the connection and try again."

    combined_data = "\n\n".join(data_sections)

    # Build the synthesis prompt
    synthesis_prompt = f"""Analyze the following IBM i system data and answer the user's question.

USER'S QUESTION: {query}

RAW SYSTEM DATA:
{combined_data}

Provide a well-formatted response following your instructions. Use tables where appropriate."""

    try:
        # Use direct OpenAI client for faster response
        from openai import OpenAI
        model_id = os.getenv("OPENROUTER_MODEL_ID", "google/gemini-2.0-flash-001")

        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("OPENROUTER_API_KEY")
        )

        response = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "system", "content": SYNTHESIS_INSTRUCTIONS_V3},
                {"role": "user", "content": synthesis_prompt}
            ],
            max_tokens=4096,
            temperature=0.3
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Error synthesizing results: {type(e).__name__}: {e}\n\nRaw data was collected but analysis failed."

# =============================================================================
# MAIN ORCHESTRATOR v3.0 - LLM-Guided Tool Selection + Dynamic SQL
# =============================================================================

class IBMiParallelAgentV3:
    """Main orchestrator for v3.0 LLM-guided architecture.

    Key improvements over v2.0:
    - LLM selects tools based on intent (not keyword matching)
    - Dynamic SQL fallback if tools don't match query
    - Max 5 SQL attempts with error feedback
    - Prettier output formatting
    """

    def __init__(self):
        self.executor = ParallelToolExecutor()

    def process_query(self, query: str) -> str:
        """Process query with LLM-guided tool selection and dynamic SQL fallback.

        Flow:
        1. LLM analyzes query and selects relevant tools
        2. Execute selected tools in parallel with streaming UI
        3. If needed, generate dynamic SQL
        4. Synthesize results with prettier formatting
        """
        # Handle special queries that don't need tools
        if self._is_config_query(query):
            return self._handle_config_query(query)

        # STEP 1: LLM selects tools (replaces keyword matching)
        if _has_rich and _console:
            _console.print("\n[cyan]Understanding your query...[/cyan]")
        else:
            print("\nUnderstanding your query...")

        selection = select_tools_with_llm(query)

        if ENABLE_AUDIT_LOG:
            print(f"[DEBUG] Tool selection: {selection}", file=sys.stderr)

        tool_results = {}
        start_time = time.time()

        # STEP 2: Execute selected tools in parallel
        if selection.get("selected_tools"):
            tools_to_run = []
            for tool_name in selection["selected_tools"]:
                if tool_name in AVAILABLE_TOOLS:
                    tool_info = AVAILABLE_TOOLS[tool_name]
                    func = tool_info.get("function")
                    if func is not None:
                        tools_to_run.append((
                            tool_name,
                            func,
                            tool_info["status_msg"]
                        ))

            if tools_to_run:
                if _has_rich and _console:
                    _console.print(f"\n[cyan]Gathering data:[/cyan] {len(tools_to_run)} sources\n")
                else:
                    print(f"\nGathering data: {len(tools_to_run)} sources\n")

                tool_results = self.executor.execute_tools_parallel(tools_to_run)

        # STEP 3: Dynamic SQL if needed or no tools selected
        if selection.get("needs_dynamic_sql") or not tool_results:
            if _has_rich and _console:
                _console.print("\n[cyan]Generating custom query...[/cyan]")
            else:
                print("\nGenerating custom query...")

            sql_result = self._execute_dynamic_sql(query, selection.get("dynamic_sql_intent", query))
            if sql_result and not sql_result.startswith("Unable to generate"):
                tool_results["dynamic-sql"] = sql_result

        gather_time = time.time() - start_time

        # STEP 4: Synthesize results with prettier formatting
        if not tool_results:
            return self._no_results_response(query)

        if _has_rich and _console:
            _console.print(f"\n[dim]Data gathered in {gather_time:.1f}s. Analyzing...[/dim]\n")
            with _console.status("[bold green]Generating report...[/bold green]", spinner="dots"):
                response = synthesize_results_v3(query, tool_results)
        else:
            print(f"\nData gathered in {gather_time:.1f}s. Analyzing...\n")
            response = synthesize_results_v3(query, tool_results)

        return response

    def _is_config_query(self, query: str) -> bool:
        """Check if query is about agent configuration."""
        q = query.lower()
        return any(phrase in q for phrase in [
            "which libraries can you access",
            "what libraries can you access",
            "allowed schemas",
            "what schemas",
            "your configuration",
            "your settings"
        ])

    def _handle_config_query(self, query: str) -> str:
        """Handle queries about agent configuration."""
        user_schemas = list(_USER_SCHEMAS) if _USER_SCHEMAS else []
        system_schemas = list(_SYSTEM_SCHEMAS)

        response = "## Accessible Libraries/Schemas\n\n"

        if user_schemas:
            response += "### User Libraries (configured in ALLOWED_USER_SCHEMAS)\n"
            response += "| Library |\n|--------|\n"
            for schema in sorted(user_schemas):
                response += f"| {schema} |\n"
            response += "\n"
        else:
            response += "### User Libraries\n"
            response += "*No user libraries configured.* Add libraries to `ALLOWED_USER_SCHEMAS` in your `.env` file.\n\n"

        response += "### System Schemas (always accessible)\n"
        response += "| Schema | Description |\n|--------|-------------|\n"
        response += "| QSYS2 | IBM i Services catalog views and table functions |\n"
        response += "| SYSTOOLS | IBM-provided SQL tools and utilities |\n"
        response += "| SYSIBM | DB2 system catalog |\n"
        response += "| QSYS | System library |\n"
        response += "| INFORMATION_SCHEMA | SQL standard metadata |\n"

        response += "\n### Adding User Libraries\n"
        response += "Edit your `.env` file:\n"
        response += "```\nALLOWED_USER_SCHEMAS=MYLIB,PRODDATA,TESTLIB\n```\n"

        return response

    def _execute_dynamic_sql(self, query: str, intent: str, attempt: int = 1, prev_sql: str = "", error: str = "") -> str:
        """Execute dynamic SQL with retry logic."""
        if attempt > MAX_SQL_ATTEMPTS:
            return f"Unable to generate valid SQL after {MAX_SQL_ATTEMPTS} attempts."

        sql_info = generate_dynamic_sql(intent or query, attempt, prev_sql, error)

        if "error" in sql_info:
            return sql_info["error"]

        if "sql" not in sql_info:
            return "No SQL generated."

        if ENABLE_AUDIT_LOG:
            print(f"[DEBUG] Dynamic SQL attempt {attempt}: {sql_info['sql'][:100]}...", file=sys.stderr)

        try:
            result = run_select(sql_info["sql"])
            if result.startswith("ERROR"):
                # Retry with error feedback
                return self._execute_dynamic_sql(
                    query, intent, attempt + 1, sql_info["sql"], result
                )
            return result
        except Exception as e:
            return self._execute_dynamic_sql(
                query, intent, attempt + 1, sql_info["sql"], str(e)
            )

    def _no_results_response(self, query: str) -> str:
        """Generate response when no data could be gathered."""
        return f"""## Unable to Process Query

I couldn't gather the necessary data to answer your question:
> {query}

**Possible reasons:**
- The query requires data from schemas not in your allowed list
- No relevant tools matched your query
- Connection issues with the IBM i system

**Suggestions:**
1. Try rephrasing your question
2. Check that required schemas are in `ALLOWED_USER_SCHEMAS`
3. Try a more specific query like "show system status" or "list user profiles"
"""

# =============================================================================
# MAIN LOOP v3.0
# =============================================================================

def main():
    # Validate environment
    try:
        creds = get_ibmi_credentials()
        print(f"[DEBUG] Connecting to IBM i at {creds['host']}:{creds['port']}...", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Failed to get IBM i credentials: {e}")
        return

    _ = _require_env("OPENROUTER_API_KEY")

    # Test connection before proceeding
    print("[DEBUG] Testing IBM i connection...", file=sys.stderr)
    try:
        conn = _get_pooled_connection_safe()
        _return_connection_safe(conn)
        print("[DEBUG] Connection test successful!", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] IBM i connection test failed: {type(e).__name__}: {e}")
        print("Please check your .env file and ensure the IBM i system is reachable.")
        return

    # Preload services
    service_count = preload_services()

    # Initialize v3.0 parallel agent with LLM-guided tool selection
    agent = IBMiParallelAgentV3()

    # Show user schemas if configured
    user_schema_info = f", User schemas: {', '.join(_USER_SCHEMAS)}" if _USER_SCHEMAS else ""

    if _has_rich and _console:
        _console.print(Panel(
            "[bold white]IBM i Parallel Agent v3.0[/bold white]\n"
            "[cyan]LLM-Guided Tool Selection + Dynamic SQL[/cyan]\n\n"
            f"[dim]Services detected: {service_count}[/dim]\n"
            f"[dim]Available tools: {len(AVAILABLE_TOOLS)}[/dim]\n"
            f"[dim]Max SQL attempts: {MAX_SQL_ATTEMPTS}[/dim]\n"
            f"[dim]Timeout: {PARALLEL_TIMEOUT}s{user_schema_info}[/dim]",
            title="[bold green]Ready[/bold green]",
            border_style="green",
            box=box.HEAVY
        ))
    else:
        print("=" * 70)
        print("IBM i Parallel Agent v3.0 - LLM-Guided Tool Selection")
        print("=" * 70)
        print(f"Services detected: {service_count}")
        print(f"Available tools: {len(AVAILABLE_TOOLS)}")
        print(f"Max SQL attempts: {MAX_SQL_ATTEMPTS}")
        print(f"Timeout: {PARALLEL_TIMEOUT}s{user_schema_info}")

    print()
    print("v3.0 improvements:")
    print("  - LLM understands your intent (no keyword matching)")
    print("  - Dynamic SQL generation for custom queries")
    print("  - Prettier output with tables and formatting\n")
    print("Example queries:")
    print("  - Why is the system slow?")
    print("  - List programs in MYLIB library")
    print("  - Which libraries can you access?")
    print("  - Show me jobs running SQL on CUSTMAST")
    print("  - Full health check")
    print()
    print("Type 'exit' to quit.\n")

    while True:
        try:
            user_input = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue

        if user_input.lower() in {"exit", "quit", "q"}:
            print("Goodbye!")
            break

        try:
            response = agent.process_query(user_input)

            # Render with Rich if available
            if _has_rich and _console:
                print()
                md = Markdown(response)
                panel = Panel(
                    md,
                    title="[bold white]Analysis Results[/bold white]",
                    border_style="green",
                    box=box.HEAVY,
                    padding=(1, 2)
                )
                _console.print(panel)
            else:
                print("\n" + response)

        except KeyboardInterrupt:
            print("\n[CANCELLED] Query cancelled")
        except Exception as e:
            print(f"\n[ERROR] {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()

        print()

if __name__ == "__main__":
    main()
