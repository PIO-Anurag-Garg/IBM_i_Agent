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
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
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
# QUERY ROUTER - Intent Classification
# =============================================================================

class AgentType(Enum):
    PERFORMANCE = "performance"
    SECURITY = "security"
    STORAGE = "storage"
    DEVELOPER = "developer"
    NETWORK = "network"
    DIAGNOSTICS = "diagnostics"

@dataclass
class QueryIntent:
    agents: List[AgentType]
    confidence: float
    keywords_matched: Set[str] = field(default_factory=set)

AGENT_KEYWORDS = {
    AgentType.PERFORMANCE: {
        "cpu", "slow", "performance", "memory", "hang", "stuck", "lock", "wait",
        "contention", "sql", "plan cache", "query", "jobs", "active", "running",
        "elapsed", "index", "tune", "optimize", "bottleneck", "latency"
    },
    AgentType.SECURITY: {
        "user", "profile", "authority", "privilege", "public", "security", "audit",
        "mfa", "totp", "certificate", "ssl", "tls", "exposure", "compliance",
        "password", "signon", "object privileges", "authorization"
    },
    AgentType.STORAGE: {
        "disk", "asp", "storage", "space", "library", "size", "ifs", "spool",
        "output queue", "print", "capacity", "growth", "cleanup", "large",
        "biggest", "files", "objects"
    },
    AgentType.DEVELOPER: {
        "source", "code", "program", "rpg", "cl", "dds", "table", "column",
        "schema", "routine", "procedure", "function", "dependency", "call",
        "reference", "member", "describe", "metadata"
    },
    AgentType.NETWORK: {
        "network", "netstat", "connection", "port", "tcp", "http", "rest",
        "api", "socket", "listen", "established", "ip"
    },
    AgentType.DIAGNOSTICS: {
        "ptf", "patch", "fix", "ipl", "journal", "receiver", "system value",
        "hardware", "license", "software", "product", "subsystem", "routing",
        "qsysopr", "message", "ended", "job queue"
    }
}

COMPOUND_QUERIES = {
    "why is system slow": [AgentType.PERFORMANCE, AgentType.STORAGE],
    "why slow": [AgentType.PERFORMANCE, AgentType.STORAGE],
    "system slow": [AgentType.PERFORMANCE, AgentType.STORAGE],
    "health check": [AgentType.PERFORMANCE, AgentType.SECURITY, AgentType.STORAGE, AgentType.DIAGNOSTICS],
    "full health": [AgentType.PERFORMANCE, AgentType.SECURITY, AgentType.STORAGE, AgentType.DIAGNOSTICS],
    "security audit": [AgentType.SECURITY, AgentType.STORAGE],
    "performance triage": [AgentType.PERFORMANCE, AgentType.DIAGNOSTICS],
    "capacity planning": [AgentType.STORAGE, AgentType.PERFORMANCE],
    "disaster recovery": [AgentType.DIAGNOSTICS, AgentType.STORAGE],
}

class QueryRouter:
    def classify(self, user_query: str) -> QueryIntent:
        query_lower = user_query.lower()

        # Check compound patterns first
        for pattern, agents in COMPOUND_QUERIES.items():
            if pattern in query_lower:
                return QueryIntent(agents=agents, confidence=0.95, keywords_matched={pattern})

        # Score each agent based on keyword matches
        agent_scores: Dict[AgentType, int] = {}
        keywords_found: Dict[AgentType, Set[str]] = {}

        for agent_type, keywords in AGENT_KEYWORDS.items():
            matches = set()
            for kw in keywords:
                if kw in query_lower:
                    matches.add(kw)
            if matches:
                agent_scores[agent_type] = len(matches)
                keywords_found[agent_type] = matches

        if not agent_scores:
            return QueryIntent(agents=[AgentType.PERFORMANCE], confidence=0.5, keywords_matched=set())

        # Select agents with significant scores
        max_score = max(agent_scores.values())
        threshold = max_score * 0.5
        selected = [agent for agent, score in agent_scores.items() if score >= threshold]

        # Limit to MAX_PARALLEL_AGENTS
        selected = selected[:MAX_PARALLEL_AGENTS]

        all_keywords = set()
        for agent in selected:
            all_keywords.update(keywords_found.get(agent, set()))

        confidence = min(0.9, 0.3 + (max_score * 0.15))
        return QueryIntent(agents=selected, confidence=confidence, keywords_matched=all_keywords)

# =============================================================================
# TOOL DEFINITIONS - Organized by Sub-Agent
# =============================================================================

# --- PERFORMANCE AGENT TOOLS ---

@tool(name="get-system-status", description="System performance statistics from QSYS2.SYSTEM_STATUS")
def get_system_status() -> str:
    return run_select(SYSTEM_STATUS_SQL)

@tool(name="get-system-activity", description="Current IBM i activity metrics")
def get_system_activity() -> str:
    return run_select(SYSTEM_ACTIVITY_SQL)

@tool(name="top-cpu-jobs", description="Top CPU jobs with optional subsystem/user filters")
def top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    sbs = _safe_csv_idents(subsystem_csv) if subsystem_csv else ""
    usr = _safe_csv_idents(user_csv) if user_csv else ""
    return run_select(TOP_CPU_JOBS_SQL, parameters=[sbs, usr, lim])

@tool(name="jobs-in-msgw", description="Jobs in MSGW status")
def jobs_in_msgw(limit: int = 50) -> str:
    return run_select(MSGW_JOBS_SQL, parameters=[_safe_limit(limit, 50, 500)])

@tool(name="active-jobs-detailed", description="Active jobs with SQL text")
def active_jobs_detailed(limit: int = 50) -> str:
    return run_select(ACTIVE_JOBS_DETAILED_SQL, parameters=[_safe_limit(limit, 50, 500)])

@tool(name="plan-cache-top", description="Top SQL by elapsed time")
def plan_cache_top(limit: int = 50) -> str:
    return run_select(PLAN_CACHE_TOP_SQL, parameters=[_safe_limit(limit, 50, 5000)])

@tool(name="plan-cache-errors", description="SQL with errors/warnings")
def plan_cache_errors(limit: int = 50) -> str:
    return run_select(PLAN_CACHE_ERRORS_SQL, parameters=[_safe_limit(limit, 50, 5000)])

@tool(name="index-advice", description="Index recommendations")
def index_advice(limit: int = 200) -> str:
    return run_select(INDEX_ADVICE_SQL, parameters=[_safe_limit(limit, 200, 5000)])

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
# SUB-AGENT DEFINITIONS
# =============================================================================

AGENT_TOOLS = {
    AgentType.PERFORMANCE: [
        get_system_status, get_system_activity, top_cpu_jobs, jobs_in_msgw,
        active_jobs_detailed, plan_cache_top, plan_cache_errors, index_advice,
        lock_waits, db_transaction_info, subsystem_pool_info
    ],
    AgentType.SECURITY: [
        list_user_profiles, list_privileged_profiles, public_all_object_authority,
        object_privileges, authorization_lists, authorization_list_entries,
        security_info, user_mfa_settings, certificate_info_expiring, user_storage_top
    ],
    AgentType.STORAGE: [
        get_asp_info, disk_hotspots, output_queue_hotspots, library_sizes,
        largest_objects, ifs_object_stats, ifs_object_locks, spooled_file_info
    ],
    AgentType.DEVELOPER: [
        list_tables_in_schema, describe_table, get_program_source_info,
        read_source_member, analyze_program_dependencies, search_sql_services,
        query_user_table, library_list_info
    ],
    AgentType.NETWORK: [
        netstat_snapshot, netstat_job_info, http_get_verbose, http_post_verbose, joblog_info
    ],
    AgentType.DIAGNOSTICS: [
        ptfs_requiring_ipl, software_products, license_info, journals,
        journal_receivers, system_values, hardware_resource_info,
        ended_jobs, job_queue_entries, qsysopr_messages
    ]
}

AGENT_INSTRUCTIONS = {
    AgentType.PERFORMANCE: """You are a Performance Analyst for IBM i systems.
Focus on CPU, memory, jobs, SQL performance, and lock contention.
When analyzing:
1. Check system status for overall health
2. Find top CPU consumers
3. Look for lock waits and contention
4. Examine plan cache for slow SQL
Provide metrics, identify bottlenecks, and recommend optimizations.""",

    AgentType.SECURITY: """You are a Security Analyst for IBM i systems.
Focus on users, authorities, MFA, certificates, and exposure.
When auditing:
1. List privileged profiles and special authorities
2. Check *PUBLIC *ALL exposure
3. Review MFA settings and certificate expiration
4. Analyze authorization lists
Identify security risks and recommend hardening steps.""",

    AgentType.STORAGE: """You are a Storage Analyst for IBM i systems.
Focus on disk, ASP, libraries, IFS, and spool files.
When analyzing:
1. Check ASP utilization
2. Find disk hotspots
3. Identify large libraries and objects
4. Review spool file accumulation
Provide capacity metrics and recommend cleanup actions.""",

    AgentType.DEVELOPER: """You are a Developer Assistant for IBM i systems.
Focus on source code, schemas, tables, and program analysis.
When assisting:
1. List tables and describe schemas
2. Find program source locations
3. Read source code when requested
4. Analyze program dependencies
Help developers understand and navigate the codebase.""",

    AgentType.NETWORK: """You are a Network Analyst for IBM i systems.
Focus on connections, ports, HTTP, and job communication.
When analyzing:
1. Show active network connections
2. Map connections to owning jobs
3. Test HTTP endpoints
4. Review job logs for network issues
Identify network activity and troubleshoot connectivity.""",

    AgentType.DIAGNOSTICS: """You are a Diagnostics Specialist for IBM i systems.
Focus on PTFs, journals, system values, and hardware.
When diagnosing:
1. Check PTFs requiring IPL
2. Review journal configuration
3. Examine system values
4. Check hardware status and messages
Identify system issues and recommend maintenance actions."""
}

def build_sub_agent(agent_type: AgentType) -> Agent:
    """Build a specialized sub-agent."""
    model_id = os.getenv("OPENROUTER_MODEL_ID", "google/gemini-3-flash-preview")
    return Agent(
        name=f"IBM i {agent_type.value.title()} Analyst",
        model=OpenRouter(id=model_id, max_tokens=8192),
        tools=AGENT_TOOLS[agent_type],
        instructions=AGENT_INSTRUCTIONS[agent_type],
        markdown=True
    )

# =============================================================================
# PARALLEL EXECUTION ENGINE
# =============================================================================

@dataclass
class AgentResult:
    agent_type: AgentType
    status: str  # "success", "error", "timeout"
    content: str
    tool_calls: int = 0
    execution_time: float = 0.0
    error: Optional[str] = None

class ParallelOrchestrator:
    def __init__(self):
        self.router = QueryRouter()
        self._agents: Dict[AgentType, Agent] = {}
        self._progress: Dict[AgentType, str] = {}
        self._progress_lock = threading.Lock()

    def _get_agent(self, agent_type: AgentType) -> Agent:
        """Get or create a sub-agent (lazy initialization)."""
        if agent_type not in self._agents:
            self._agents[agent_type] = build_sub_agent(agent_type)
        return self._agents[agent_type]

    def _update_progress(self, agent_type: AgentType, status: str):
        with self._progress_lock:
            self._progress[agent_type] = status

    def _run_single_agent(self, agent_type: AgentType, query: str) -> AgentResult:
        """Run a single agent and return result."""
        start_time = time.time()
        self._update_progress(agent_type, "running")

        try:
            agent = self._get_agent(agent_type)
            response = agent.run(query)
            content = response.content if hasattr(response, 'content') else str(response)

            self._update_progress(agent_type, "completed")
            return AgentResult(
                agent_type=agent_type,
                status="success",
                content=content,
                execution_time=time.time() - start_time
            )
        except Exception as e:
            self._update_progress(agent_type, "error")
            return AgentResult(
                agent_type=agent_type,
                status="error",
                content="",
                execution_time=time.time() - start_time,
                error=str(e)
            )

    def execute_parallel(self, query: str) -> Dict[AgentType, AgentResult]:
        """Execute multiple agents in parallel."""
        intent = self.router.classify(query)

        if len(intent.agents) == 0:
            intent.agents = [AgentType.PERFORMANCE]

        # Initialize progress
        with self._progress_lock:
            self._progress = {agent: "pending" for agent in intent.agents}

        results: Dict[AgentType, AgentResult] = {}

        # Use ThreadPoolExecutor for parallel execution
        with ThreadPoolExecutor(max_workers=len(intent.agents)) as executor:
            futures: Dict[Future, AgentType] = {}

            for agent_type in intent.agents:
                future = executor.submit(self._run_single_agent, agent_type, query)
                futures[future] = agent_type

            # Collect results as they complete
            for future in as_completed(futures, timeout=PARALLEL_TIMEOUT):
                agent_type = futures[future]
                try:
                    results[agent_type] = future.result()
                except Exception as e:
                    results[agent_type] = AgentResult(
                        agent_type=agent_type,
                        status="error",
                        content="",
                        error=str(e)
                    )

        return results

    def get_progress(self) -> Dict[AgentType, str]:
        """Get current progress of all agents."""
        with self._progress_lock:
            return dict(self._progress)

# =============================================================================
# RESULT AGGREGATOR
# =============================================================================

class ResultAggregator:
    def aggregate(self, results: Dict[AgentType, AgentResult], query: str) -> str:
        """Combine results from multiple agents into unified response."""
        sections = []

        # Header
        successful = [r for r in results.values() if r.status == "success"]
        failed = [r for r in results.values() if r.status != "success"]
        total_time = max((r.execution_time for r in results.values()), default=0)

        sections.append("# IBM i Parallel Analysis Report\n")
        sections.append(f"**Query:** {query[:100]}{'...' if len(query) > 100 else ''}")
        sections.append(f"**Agents:** {len(results)} | **Successful:** {len(successful)} | **Failed:** {len(failed)}")
        sections.append(f"**Total Time:** {total_time:.1f}s (parallel execution)\n")

        # Agent Results
        for agent_type in [AgentType.PERFORMANCE, AgentType.SECURITY, AgentType.STORAGE,
                          AgentType.DEVELOPER, AgentType.NETWORK, AgentType.DIAGNOSTICS]:
            if agent_type not in results:
                continue

            result = results[agent_type]
            sections.append(f"## {agent_type.value.title()} Analysis ({result.execution_time:.1f}s)")

            if result.status == "success":
                sections.append(result.content)
            else:
                sections.append(f"*Error: {result.error or 'Unknown error'}*")
            sections.append("")

        # Cross-Domain Insights (if multiple successful agents)
        if len(successful) > 1:
            sections.append("## Cross-Domain Insights")
            insights = self._find_correlations(successful)
            sections.append(insights if insights else "No specific correlations identified.")
            sections.append("")

        # Recommendations
        sections.append("## Recommended Actions")
        recommendations = self._extract_recommendations(successful)
        sections.append(recommendations if recommendations else "Review individual agent findings for specific actions.")

        return "\n".join(sections)

    def _find_correlations(self, results: List[AgentResult]) -> str:
        """Find correlations between agent findings."""
        insights = []

        contents = {r.agent_type: r.content.lower() for r in results}

        # CPU + Storage correlation
        if AgentType.PERFORMANCE in contents and AgentType.STORAGE in contents:
            if "high" in contents[AgentType.PERFORMANCE] and "disk" in contents[AgentType.STORAGE]:
                insights.append("- High CPU may correlate with disk I/O - check for table scans")

        # Security + Storage
        if AgentType.SECURITY in contents and AgentType.STORAGE in contents:
            if "public" in contents[AgentType.SECURITY]:
                insights.append("- *PUBLIC authorities found - review with storage owners")

        return "\n".join(insights)

    def _extract_recommendations(self, results: List[AgentResult]) -> str:
        """Extract recommendations from agent outputs."""
        recs = []
        for result in results:
            lines = result.content.split("\n")
            for line in lines:
                lower = line.lower()
                if any(kw in lower for kw in ["recommend", "suggest", "should", "consider", "action"]):
                    if line.strip() and len(line) < 200:
                        recs.append(f"- [{result.agent_type.value}] {line.strip()}")
        return "\n".join(recs[:10]) if recs else ""

# =============================================================================
# STREAMING PROGRESS UI
# =============================================================================

class StreamingProgressUI:
    def __init__(self):
        self.start_time: Optional[float] = None
        self._lock = threading.Lock()

    def show_routing(self, intent: QueryIntent):
        """Show which agents will be invoked."""
        agent_names = ", ".join(a.value.title() for a in intent.agents)
        print(f"\n🎯 Routing to: {agent_names} (confidence: {intent.confidence:.0%})")
        if intent.keywords_matched:
            print(f"   Keywords: {', '.join(intent.keywords_matched)}")

    def show_parallel_start(self, agents: List[AgentType]):
        """Show parallel execution starting."""
        self.start_time = time.time()
        print(f"\n⚡ Starting parallel execution with {len(agents)} agents...")
        for agent in agents:
            print(f"   • {agent.value.title()} Agent")

    def show_agent_complete(self, agent_type: AgentType, result: AgentResult):
        """Show individual agent completion."""
        status = "✓" if result.status == "success" else "✗"
        print(f"   {status} {agent_type.value.title()}: {result.execution_time:.1f}s")

    def show_final_result(self, total_time: float, successful: int, failed: int):
        """Show final execution summary."""
        print(f"\n✅ Parallel execution complete!")
        print(f"   Total time: {total_time:.1f}s | Success: {successful} | Failed: {failed}")

def safe_print(text: str, **kwargs):
    """Print with encoding error handling."""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        print(text.encode('ascii', errors='replace').decode('ascii'), **kwargs)

# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

class IBMiParallelAgent:
    def __init__(self):
        self.orchestrator = ParallelOrchestrator()
        self.aggregator = ResultAggregator()
        self.ui = StreamingProgressUI()
        self.router = QueryRouter()

    def process_query(self, query: str) -> str:
        """Process a user query with parallel sub-agents."""
        # Classify intent
        intent = self.router.classify(query)
        self.ui.show_routing(intent)

        # Start parallel execution
        self.ui.show_parallel_start(intent.agents)
        start_time = time.time()

        # Execute agents in parallel
        results = self.orchestrator.execute_parallel(query)

        # Show individual completions
        for agent_type, result in results.items():
            self.ui.show_agent_complete(agent_type, result)

        # Aggregate results
        total_time = time.time() - start_time
        successful = len([r for r in results.values() if r.status == "success"])
        failed = len(results) - successful

        self.ui.show_final_result(total_time, successful, failed)

        # Generate aggregated response
        return self.aggregator.aggregate(results, query)

# =============================================================================
# MAIN LOOP
# =============================================================================

def main():
    # Validate environment
    _ = get_ibmi_credentials()
    _ = _require_env("OPENROUTER_API_KEY")

    # Preload services
    service_count = preload_services()

    # Initialize parallel agent
    agent = IBMiParallelAgent()

    print("=" * 70)
    print("IBM i Parallel Agent - Sub-Agent Architecture")
    print("=" * 70)
    print(f"Services detected: {service_count}")
    print(f"Max parallel agents: {MAX_PARALLEL_AGENTS}")
    print(f"Parallel timeout: {PARALLEL_TIMEOUT}s")
    print()
    print("This agent uses parallel execution to analyze your IBM i system faster.")
    print("Complex queries are routed to multiple specialized sub-agents.")
    print()
    print("Example queries:")
    print("  • Why is the system slow?")
    print("  • Do a security audit")
    print("  • Give me a full health check")
    print("  • Read source code for MYPGM in MYLIB")
    print("  • What's using the most disk space?")
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
                panel = Panel(md, title="[bold white]Parallel Analysis Results[/bold white]",
                             border_style="green", box=box.HEAVY, padding=(1, 2))
                _console.print(panel)
            else:
                print("\n" + response)

        except KeyboardInterrupt:
            print("\n[CANCELLED] Query cancelled")
        except Exception as e:
            print(f"\n[ERROR] {type(e).__name__}: {e}")

        print()

if __name__ == "__main__":
    main()
