
import os
import re
import json
import time
from datetime import datetime, timezone
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

def run_sql_statement(
    sql: str,
    parameters: Optional[QueryParameters] = None,
    creds: Optional[Dict[str, Any]] = None,
) -> str:
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
# SAFETY HELPERS
# =============================================================================

_SAFE_IDENT = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)

# Allow queries against known system schemas (IBM i Services + catalogs)
_ALLOWED_SCHEMAS = {"QSYS2", "SYSTOOLS", "SYSIBM", "QSYS", "INFORMATION_SCHEMA"}

_FORBIDDEN_SQL_TOKENS = re.compile(
    r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bMERGE\b|\bDROP\b|\bALTER\b|\bCREATE\b|\bCALL\b|\bGRANT\b|\bREVOKE\b|\bQCMDEXC\b)",
    re.IGNORECASE,
)

def _safe_ident(value: str, what: str = "identifier") -> str:
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
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
    _looks_like_safe_select(sql)
    try:
        return run_sql_statement(sql, parameters=parameters)
    except Exception as e:
        return f"ERROR executing SQL. Details: {type(e).__name__}: {e}"

# =============================================================================
# AUDIT LOGGING (Router decisions + run metadata)
# =============================================================================

def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def audit_log_event(event: Dict[str, Any]) -> None:
    """
    Writes JSONL to file for auditability. Optionally logs to Db2 if enabled.
    """
    event = dict(event)
    event.setdefault("ts", _now_utc_iso())
    event.setdefault("app", "ibmi-agent-suite")

    # File logging
    log_path = os.getenv("ROUTER_AUDIT_LOG", "router_audit.jsonl")
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except Exception:
        pass

    # Optional DB logging (disabled by default)
    if os.getenv("ENABLE_DB_AUDIT_LOG", "").strip().lower() in {"1", "true", "yes", "y"}:
        # Create this table yourself if you want DB logging:
        # CREATE TABLE SAMPLE.AGENT_AUDIT (
        #   TS TIMESTAMP NOT NULL,
        #   ROUTE_AGENT VARCHAR(20),
        #   CONFIDENCE DECIMAL(5,4),
        #   USER_QUERY CLOB(1M),
        #   DETAILS CLOB(1M)
        # )
        try:
            sql = """
                INSERT INTO SAMPLE.AGENT_AUDIT (TS, ROUTE_AGENT, CONFIDENCE, USER_QUERY, DETAILS)
                VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?)
            """
            run_sql_statement(
                sql,
                parameters=[
                    event.get("route_agent"),
                    float(event.get("confidence") or 0.0),
                    (event.get("user_query") or "")[:200000],
                    json.dumps(event, default=str)[:200000],
                ],
            )
        except Exception:
            pass

# =============================================================================
# SQL TEMPLATES (IBM i Services / Catalogs)
# =============================================================================

SYSTEM_STATUS_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS(RESET_STATISTICS => 'NO', DETAILED_INFO => 'ALL')) X"
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

LICENSE_INFO_SQL = """
SELECT *
FROM QSYS2.LICENSE_INFO
ORDER BY PRODUCT_ID
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
# TOOLING (READ-ONLY + optional logging insert)
# =============================================================================

@tool(name="get-system-status", description="Retrieve IBM i system performance statistics using QSYS2.SYSTEM_STATUS.")
def get_system_status() -> str:
    return run_select(SYSTEM_STATUS_SQL)

@tool(name="get-system-activity", description="Retrieve IBM i activity metrics using QSYS2.SYSTEM_ACTIVITY_INFO.")
def get_system_activity() -> str:
    return run_select(SYSTEM_ACTIVITY_SQL)

@tool(name="top-cpu-jobs", description="Top CPU jobs using QSYS2.ACTIVE_JOB_INFO. Optional subsystem/user CSV filters.")
def top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    sbs = _safe_csv_idents(subsystem_csv, what="subsystem list") if subsystem_csv else ""
    usr = _safe_csv_idents(user_csv, what="user list") if user_csv else ""
    return run_select(TOP_CPU_JOBS_SQL, parameters=[sbs, usr, lim])

@tool(name="jobs-in-msgw", description="List MSGW jobs using QSYS2.ACTIVE_JOB_INFO.")
def jobs_in_msgw(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    return run_select(MSGW_JOBS_SQL, parameters=[lim])

@tool(name="qsysopr-messages", description="Fetch recent QSYSOPR messages using QSYS2.MESSAGE_QUEUE_INFO.")
def qsysopr_messages(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=500)
    return run_select(QSYSOPR_RECENT_MSGS_SQL, parameters=[lim])

@tool(name="netstat-snapshot", description="Network connections snapshot using QSYS2.NETSTAT_INFO.")
def netstat_snapshot(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=1000)
    return run_select(NETSTAT_SUMMARY_SQL, parameters=[lim])

@tool(name="get-asp-info", description="ASP usage information using QSYS2.ASP_INFO.")
def get_asp_info() -> str:
    return run_select(ASP_INFO_SQL)

@tool(name="disk-hotspots", description="Disk hotspots using QSYS2.SYSDISKSTAT.")
def disk_hotspots(limit: int = 10) -> str:
    lim = _safe_limit(limit, default=10, max_n=200)
    return run_select(DISK_HOTSPOTS_SQL, parameters=[lim])

@tool(name="output-queue-hotspots", description="Spool hotspots using QSYS2.OUTPUT_QUEUE_INFO.")
def output_queue_hotspots(limit: int = 20) -> str:
    lim = _safe_limit(limit, default=20, max_n=500)
    return run_select(OUTQ_HOTSPOTS_SQL, parameters=[lim])

@tool(name="search-sql-services", description="Search IBM i SQL services catalog using QSYS2.SERVICES_INFO.")
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

@tool(name="list-privileged-profiles", description="List privileged profiles using QSYS2.USER_INFO.")
def list_privileged_profiles(limit: int = 500) -> str:
    lim = _safe_limit(limit, default=500, max_n=5000)
    return run_select(USER_INFO_PRIVILEGED_SQL, parameters=[lim])

@tool(name="public-all-object-authority", description="List objects where *PUBLIC has *ALL authority using QSYS2.OBJECT_PRIVILEGES.")
def public_all_object_authority(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(PUBLIC_ALL_OBJECTS_SQL, parameters=[lim])

@tool(name="ptfs-requiring-ipl", description="List PTFs requiring IPL using QSYS2.PTF_INFO.")
def ptfs_requiring_ipl(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=2000)
    return run_select(PTF_IPL_REQUIRED_SQL, parameters=[lim])

@tool(name="license-info", description="List license info using QSYS2.LICENSE_INFO.")
def license_info(limit: int = 200) -> str:
    lim = _safe_limit(limit, default=200, max_n=5000)
    return run_select(LICENSE_INFO_SQL, parameters=[lim])

@tool(name="largest-objects", description="Largest objects in a library using QSYS2.OBJECT_STATISTICS.")
def largest_objects(library: str, limit: int = 50) -> str:
    lib = _safe_ident(library, what="library")
    lim = _safe_limit(limit, default=50, max_n=5000)
    return run_select(LARGEST_OBJECTS_SQL, parameters=[lib, lim])

@tool(name="library-sizes", description="List libraries and sizes using QSYS2.LIBRARY_INFO. Optionally exclude system libraries.")
def library_sizes(limit: int = 100, exclude_system: bool = False) -> str:
    lim = _safe_limit(limit, default=100, max_n=20000)
    sql = LIBRARY_SIZES_EXCL_SYSTEM_SQL if exclude_system else LIBRARY_SIZES_ALL_SQL
    return run_select(sql, parameters=[lim])

# Optional metrics logging (write) - safe for trending, not required for read-only Q&A
@tool(
    name="log-performance-metrics",
    description="Insert metrics into SAMPLE.METRICS for trend history (optional; table must exist).",
)
def log_performance_metrics(cpu_usage: float, asp_usage: float) -> str:
    sql = """
        INSERT INTO SAMPLE.METRICS (TS, CPU_PCT, ASP_PCT)
        VALUES (CURRENT_TIMESTAMP, ?, ?)
    """
    try:
        return run_sql_statement(sql, parameters=[cpu_usage, asp_usage])
    except Exception as e:
        return f"ERROR inserting metrics. Details: {type(e).__name__}: {e}"

# =============================================================================
# ACTION TOOL SCAFFOLD (DISABLED BY DEFAULT)
# - For future: controlled changes with human confirmation
# =============================================================================

def _actions_enabled() -> bool:
    return os.getenv("ENABLE_ACTION_TOOLS", "").strip().lower() in {"1", "true", "yes", "y"}

@tool(
    name="propose-controlled-change",
    description="Creates a controlled change plan (non-executing). Always safe.",
)
def propose_controlled_change(change_goal: str) -> str:
    return dedent(f"""
    # Controlled Change Plan (Non-Executing)
    **Goal:** {change_goal}

    ## Steps
    1. Collect evidence (jobs, messages, disk/ASP, SQL plans as applicable).
    2. Draft a rollback plan.
    3. Obtain approvals (change mgmt + system owner).
    4. Execute in a maintenance window.
    5. Validate post-change and record results.

    ## Notes
    - This assistant will not execute changes unless ENABLE_ACTION_TOOLS is enabled
      and the request is explicitly confirmed by an operator.
    """).strip()

@tool(
    name="action-apply-ptf-group",
    description="(Controlled) Apply PTF group - placeholder. Requires actions enabled and human confirmation.",
    requires_confirmation=True,  # supported by Agno tool decorator
)
def action_apply_ptf_group(ptf_group: str) -> str:
    if not _actions_enabled():
        return "ACTIONS DISABLED. Set ENABLE_ACTION_TOOLS=1 and re-run. Then confirm explicitly."
    # Placeholder: real implementation would call a safe external executor / runbook automation.
    return f"REQUEST RECEIVED (SIMULATED): Would apply PTF group {ptf_group}. Implement actual automation separately."

# =============================================================================
# AGENT BUILDERS (12 AGENTS)
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
        - Use ONLY the provided tools for IBM i data retrieval.
        - Use 'search-sql-services' if you suspect another IBM i Service exists to answer the question.

        Output format:
        - Use Markdown.
        - Provide: Summary, Evidence (tool results), Interpretation, Next actions.
        - Never invent system data.

        Safety:
        - Default to read-only analysis.
        - If a user asks for changes/actions, provide a controlled plan via propose-controlled-change.
        - Only use explicit action tools if ENABLE_ACTION_TOOLS=1 and user confirms.
        """
    ).strip()

def build_ops_agent() -> Agent:
    return Agent(
        name="Ops & Observability Agent",
        model=_model(),
        tools=[
            get_system_status, get_system_activity, top_cpu_jobs, jobs_in_msgw,
            qsysopr_messages, netstat_snapshot, get_asp_info, disk_hotspots,
            output_queue_hotspots, library_sizes, largest_objects,
            search_sql_services, propose_controlled_change
        ],
        instructions=_base_instructions(
            "Ops & Observability Agent",
            "System health, jobs/subsystems, MSGW triage, QSYSOPR review, network snapshot, disk/ASP utilization."
        ),
        markdown=True,
    )

def build_security_agent() -> Agent:
    return Agent(
        name="Security & Compliance Agent",
        model=_model(),
        tools=[
            list_user_profiles, list_privileged_profiles, public_all_object_authority,
            search_sql_services, propose_controlled_change
        ],
        instructions=_base_instructions(
            "Security & Compliance Agent",
            "Profiles/authorities posture, risky *PUBLIC authorities, compliance evidence."
        ),
        markdown=True,
    )

def build_sql_perf_agent() -> Agent:
    return Agent(
        name="Db2 SQL Performance Agent",
        model=_model(),
        tools=[
            get_system_activity, top_cpu_jobs, search_sql_services,
            propose_controlled_change
        ],
        instructions=_base_instructions(
            "Db2 SQL Performance Agent",
            "SQL performance triage and tuning recommendations; uses available evidence tools in this script."
        ),
        markdown=True,
    )

def build_modernize_agent() -> Agent:
    return Agent(
        name="RPG/CL Modernization Agent",
        model=_model(),
        tools=[search_sql_services, propose_controlled_change],
        instructions=_base_instructions(
            "RPG/CL Modernization Agent",
            "Modernization guidance, refactoring patterns, safe migration plans (non-executing)."
        ),
        markdown=True,
    )

def build_devops_agent() -> Agent:
    return Agent(
        name="DevOps & Release Agent",
        model=_model(),
        tools=[ptfs_requiring_ipl, license_info, search_sql_services, propose_controlled_change],
        instructions=_base_instructions(
            "DevOps & Release Agent",
            "PTF/IPL planning, licensing checks, release readiness and rollback planning."
        ),
        markdown=True,
    )

def build_integration_agent() -> Agent:
    return Agent(
        name="Integration & API Agent",
        model=_model(),
        tools=[search_sql_services, propose_controlled_change],
        instructions=_base_instructions(
            "Integration & API Agent",
            "Integration planning, REST/TLS guidance, secure patterns (non-executing)."
        ),
        markdown=True,
    )

def build_streaming_agent() -> Agent:
    return Agent(
        name="Event Streaming / CDC Agent",
        model=_model(),
        tools=[search_sql_services, propose_controlled_change],
        instructions=_base_instructions(
            "Event Streaming / CDC Agent",
            "Journaling/CDC/event streaming architecture guidance (non-executing)."
        ),
        markdown=True,
    )

def build_hadr_agent() -> Agent:
    return Agent(
        name="HA/DR & Cyber Resilience Agent",
        model=_model(),
        tools=[library_sizes, largest_objects, search_sql_services, propose_controlled_change],
        instructions=_base_instructions(
            "HA/DR & Cyber Resilience Agent",
            "HA/DR readiness guidance, backup posture, ransomware resilience planning (non-executing)."
        ),
        markdown=True,
    )

def build_capacity_agent() -> Agent:
    return Agent(
        name="Capacity & Cost Optimization Agent",
        model=_model(),
        tools=[get_system_status, get_system_activity, top_cpu_jobs, get_asp_info, disk_hotspots, library_sizes, propose_controlled_change],
        instructions=_base_instructions(
            "Capacity & Cost Optimization Agent",
            "Capacity snapshots, growth drivers, optimization ideas, and planning (non-executing)."
        ),
        markdown=True,
    )

def build_ai_strategy_agent() -> Agent:
    return Agent(
        name="AI Enablement & Platform Strategy Agent",
        model=_model(),
        tools=[search_sql_services, propose_controlled_change],
        instructions=_base_instructions(
            "AI Enablement & Platform Strategy Agent",
            "Agent readiness strategy, guardrails, hybrid architecture choices, pilot planning."
        ),
        markdown=True,
    )

def build_data_governance_agent() -> Agent:
    return Agent(
        name="Data Governance & Discovery Agent",
        model=_model(),
        tools=[search_sql_services, propose_controlled_change],
        instructions=_base_instructions(
            "Data Governance & Discovery Agent",
            "Metadata discovery strategies, data dictionary patterns, and governance planning."
        ),
        markdown=True,
    )

def build_helpdesk_agent() -> Agent:
    return Agent(
        name="IBM i Helpdesk Agent",
        model=_model(),
        tools=[qsysopr_messages, jobs_in_msgw, top_cpu_jobs, ptfs_requiring_ipl, public_all_object_authority, propose_controlled_change],
        instructions=_base_instructions(
            "IBM i Helpdesk Agent",
            "First-line triage, explanations, evidence gathering, and ticket-ready summaries."
        ),
        markdown=True,
    )

# Optional: Action agent (not used unless actions enabled AND explicitly routed)
def build_action_agent() -> Agent:
    return Agent(
        name="Controlled Change Execution Agent (Restricted)",
        model=_model(),
        tools=[propose_controlled_change, action_apply_ptf_group],
        instructions=_base_instructions(
            "Controlled Change Execution Agent (Restricted)",
            "Only executes controlled actions when ENABLE_ACTION_TOOLS=1 and user explicitly confirms."
        ),
        markdown=True,
    )

AGENT_BUILDERS: Dict[str, Callable[[], Agent]] = {
    "ops": build_ops_agent,
    "security": build_security_agent,
    "sqlperf": build_sql_perf_agent,
    "modernize": build_modernize_agent,
    "devops": build_devops_agent,
    "integration": build_integration_agent,
    "streaming": build_streaming_agent,
    "hadr": build_hadr_agent,
    "capacity": build_capacity_agent,
    "aistrategy": build_ai_strategy_agent,
    "datagov": build_data_governance_agent,
    "helpdesk": build_helpdesk_agent,
    # action agent only used when enabled and explicitly confirmed
    "actions": build_action_agent,
}

def build_all_agents() -> Dict[str, Agent]:
    agents = {k: v() for k, v in AGENT_BUILDERS.items() if k != "actions"}
    # Only instantiate action agent if actions enabled (reduces accidental exposure)
    if _actions_enabled():
        agents["actions"] = build_action_agent()
    return agents

# =============================================================================
# HYBRID ROUTER
# =============================================================================

# Deterministic hard-gate keyword sets (transparent + auditable)
SECURITY_KW = ("authority", "authorities", "alobj", "*allobj", "secadm", "mfa", "audit", "qaud", "password", "signon", "profile")
SQL_KW = ("sql", "query", "index", "plan", "cache", "lock", "deadlock", "wait", "statement", "optimizer")
OPS_KW = ("cpu", "jobs", "subsystem", "msgw", "qsysopr", "disk", "asp", "netstat", "connections", "spool", "outq", "performance", "slow", "hang")
DEVOPS_KW = ("ptf", "ipl", "release", "deploy", "rollback", "promotion", "drift", "license")
INTEGRATION_KW = ("rest", "http", "https", "api", "oauth", "jwt", "tls", "certificate", "webhook")
STREAMING_KW = ("kafka", "cdc", "event", "stream", "journal", "journaling", "topic", "replay")
HADR_KW = ("ha", "dr", "disaster", "backup", "restore", "powerha", "ransomware", "resilience", "switchover", "failover")
CAPACITY_KW = ("capacity", "forecast", "growth", "headroom", "utilization", "peak", "cost", "storage growth")
MODERNIZE_KW = ("rpg", "cl", "free-form", "refactor", "service program", "modernize", "documentation")
DATAGOV_KW = ("schema", "table", "column", "dictionary", "lineage", "metadata", "source of truth", "dependencies")
AISTRATEGY_KW = ("ai", "agent", "rag", "embeddings", "watsonx", "granite", "pilot", "governance", "guardrails")
ACTION_KW = ("apply", "change", "execute", "run command", "fix", "set", "enable", "disable", "grant", "revoke", "delete", "create", "alter")

def deterministic_route(user_q: str) -> Optional[str]:
    s = (user_q or "").strip().lower()

    # Explicit routing override: /agent security: ...
    if s.startswith("/agent"):
        rest = s[len("/agent"):].strip()
        for key in AGENT_BUILDERS.keys():
            if rest.startswith(key):
                if key == "actions" and not _actions_enabled():
                    return "helpdesk"
                return key
        return "helpdesk"

    # Hard gates (security first)
    if any(k in s for k in SECURITY_KW):
        return "security"
    if any(k in s for k in SQL_KW):
        return "sqlperf"
    if any(k in s for k in INTEGRATION_KW):
        return "integration"
    if any(k in s for k in STREAMING_KW):
        return "streaming"
    if any(k in s for k in HADR_KW):
        return "hadr"
    if any(k in s for k in DEVOPS_KW):
        return "devops"
    if any(k in s for k in CAPACITY_KW):
        return "capacity"
    if any(k in s for k in DATAGOV_KW):
        return "datagov"
    if any(k in s for k in MODERNIZE_KW):
        return "modernize"
    if any(k in s for k in AISTRATEGY_KW):
        return "aistrategy"
    if any(k in s for k in OPS_KW):
        return "ops"

    # No deterministic decision
    return None

def _router_model_agent() -> Agent:
    """
    LLM router agent: returns STRICT JSON.
    """
    return Agent(
        name="Hybrid Router (Classifier)",
        model=_model(),
        tools=[],
        instructions=dedent("""
        You are a strict routing classifier for an IBM i multi-agent assistant.

        Return ONLY valid JSON (no markdown, no prose) with this schema:
        {
          "agent": "<one of: ops, security, sqlperf, modernize, devops, integration, streaming, hadr, capacity, aistrategy, datagov, helpdesk>",
          "confidence": <float 0.0-1.0>,
          "reason": "<short>",
          "secondary_agents": ["<agent>", ...]  // optional, max 2
        }

        Rules:
        - Pick "helpdesk" if uncertain or the query is general.
        - If it is clearly multi-intent, choose a primary and up to 2 secondary agents.
        - NEVER return "actions" (that is reserved for explicit controlled execution).
        """).strip(),
        markdown=False,
    )

def model_route(user_q: str, router_agent: Agent) -> Dict[str, Any]:
    """
    Use Agent.run() to classify. If parsing fails, fall back to helpdesk.
    """
    try:
        resp = router_agent.run(user_q)  # RunResponse with .content per docs
        raw = getattr(resp, "content", None) or str(resp)
        data = json.loads(raw)
        # Validate minimal schema
        agent = data.get("agent", "helpdesk")
        if agent not in {"ops","security","sqlperf","modernize","devops","integration","streaming","hadr","capacity","aistrategy","datagov","helpdesk"}:
            agent = "helpdesk"
        conf = float(data.get("confidence", 0.0))
        reason = str(data.get("reason", ""))[:500]
        sec = data.get("secondary_agents") or []
        if not isinstance(sec, list):
            sec = []
        sec = [a for a in sec if a in {"ops","security","sqlperf","modernize","devops","integration","streaming","hadr","capacity","aistrategy","datagov","helpdesk"}]
        sec = sec[:2]
        return {"agent": agent, "confidence": conf, "reason": reason, "secondary_agents": sec}
    except Exception as e:
        return {"agent": "helpdesk", "confidence": 0.0, "reason": f"router_parse_error:{type(e).__name__}", "secondary_agents": []}

def hybrid_route(user_q: str, router_agent: Agent) -> Dict[str, Any]:
    """
    Hybrid routing:
    1) deterministic hard gates
    2) LLM classifier if ambiguous
    3) action gating: if user is asking for changes, route to a safe agent and provide plan
    """
    s = (user_q or "").strip().lower()
    det = deterministic_route(user_q)

    # If user asks for actions/changes: keep it out of action execution by default
    wants_action = any(k in s for k in ACTION_KW)

    if det:
        chosen = {"agent": det, "confidence": 1.0, "reason": "deterministic_match", "secondary_agents": []}
    else:
        chosen = model_route(user_q, router_agent)
        # If low confidence, route to helpdesk for safer triage
        if chosen["confidence"] < float(os.getenv("ROUTER_CONFIDENCE_THRESHOLD", "0.65")):
            chosen = {"agent": "helpdesk", "confidence": chosen["confidence"], "reason": "low_confidence_fallback", "secondary_agents": []}

    # Enforce action safety
    if wants_action:
        # never auto-route to actions agent
        chosen["reason"] = (chosen.get("reason","") + "|action_intent_detected").strip("|")
        # Ensure we land on an agent that can propose plans
        if chosen["agent"] not in {"devops", "security", "ops", "sqlperf", "hadr", "helpdesk"}:
            chosen["agent"] = "helpdesk"
        # secondary agents still allowed but keep it small
        chosen["secondary_agents"] = [a for a in chosen.get("secondary_agents", []) if a != "actions"][:2]

    return chosen

# =============================================================================
# RUN LOOP (supports multi-agent follow-ups when router returns secondary_agents)
# =============================================================================

def run_agent_and_print(agent: Agent, user_q: str) -> str:
    """
    Uses Agent.run() so we can capture content + log metadata reliably.
    """
    resp = agent.run(user_q)
    content = getattr(resp, "content", None) or str(resp)
    print(content)
    return content

def main() -> None:
    # Fail fast if required env vars are not present
    _ = get_ibmi_credentials()
    _ = _require_env("ANTHROPIC_API_KEY")

    agents = build_all_agents()
    router_agent = _router_model_agent()

    print("\n✅ IBM i Multi-Agent Suite (Hybrid Router) is ready.")
    print("\nAgents available:")
    for k, a in agents.items():
        print(f" - {k:10s} : {a.name}")
    print("\nTips:")
    print(" - Ask normally; hybrid router picks the best agent.")
    print(" - Force routing: /agent security: list risky *PUBLIC authorities")
    print(" - Enable controlled actions (future): set ENABLE_ACTION_TOOLS=1 (tools still require confirmation).")
    print(" - Exit: type 'exit'\n")

    while True:
        user_q = input("You> ").strip()
        if user_q.lower() in {"exit", "quit"}:
            break
        if not user_q:
            continue

        route = hybrid_route(user_q, router_agent)
        primary_key = route["agent"]
        secondary_keys = route.get("secondary_agents", [])

        primary_agent = agents.get(primary_key, agents["helpdesk"])

        # Audit routing decision
        audit_log_event({
            "route_agent": primary_key,
            "confidence": route.get("confidence"),
            "reason": route.get("reason"),
            "secondary_agents": secondary_keys,
            "user_query": user_q,
            "actions_enabled": _actions_enabled(),
        })

        print(f"\n[Routing -> {primary_key} | {primary_agent.name} | conf={route.get('confidence'):.2f}]\n")
        primary_out = run_agent_and_print(primary_agent, user_q)

        # Optional follow-up runs for multi-intent (kept short to reduce noise)
        for sk in secondary_keys:
            if sk == primary_key:
                continue
            sec_agent = agents.get(sk)
            if not sec_agent:
                continue
            print(f"\n[Secondary -> {sk} | {sec_agent.name}]\n")
            # Provide context summary safely (no hidden system data, just previous output)
            followup_q = f"""
            The user asked: {user_q}

            The primary agent responded:
            {primary_out}

            Provide additional evidence or next steps from your specialty.
            """
            run_agent_and_print(sec_agent, followup_q.strip())

if __name__ == "__main__":
    main()