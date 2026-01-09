
import os
import re
import json
from textwrap import dedent
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from mapepire_python import connect
from pep249 import QueryParameters

from agno.agent import Agent
from agno.models.anthropic import Claude
from agno.tools import tool

# Load environment variables from .env file
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
                # Common Mapepire shape: {"metadata": ..., "data": ...}
                if isinstance(raw, dict) and "data" in raw:
                    return format_mapepire_result(raw["data"])
                return format_mapepire_result(raw)
            return "SQL executed successfully. No results returned."


# =============================================================================
# SAFETY HELPERS (Prevent SQL injection; allow only safe identifiers & SELECT tools)
# =============================================================================

_SAFE_IDENT = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)


def _safe_ident(value: str, what: str = "identifier") -> str:
    """
    Validate an IBM i-ish identifier (library, object, user, subsystem, etc.)
    Keeps us out of SQL injection while still allowing typical IBM i names.
    """
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()


def _safe_csv_idents(value: str, what: str = "list") -> str:
    """
    Validate comma-separated identifiers (e.g. 'QSYSWRK,QBATCH').
    Returns normalized CSV string in upper-case with no spaces.
    """
    parts = [p.strip() for p in (value or "").split(",") if p.strip()]
    if not parts:
        return ""
    norm = [_safe_ident(p, what=what) for p in parts]
    return ",".join(norm)


def _safe_limit(n: int, default: int = 10, max_n: int = 200) -> int:
    try:
        n = int(n)
    except Exception:
        return default
    return max(1, min(n, max_n))


def run_select(sql: str, parameters: Optional[QueryParameters] = None) -> str:
    """
    Guardrail: only allow read-only SELECT/WITH statements through tools that call this helper.
    """
    head = (sql or "").lstrip().upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise ValueError("Only SELECT/WITH statements are allowed by this helper.")
    return run_sql_statement(sql, parameters=parameters)


# =============================================================================
# IBM i SQL Services (Original + New)
# =============================================================================

# --- Original services from your article example ---
SYSTEM_STATUS_SQL = (
    "SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS(RESET_STATISTICS=>'YES', DETAILED_INFO=>'ALL')) X"
)
SYSTEM_ACTIVITY_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_ACTIVITY_INFO())"

# --- New IBM i “amazing” services ---
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
       CPU_TIME
FROM TABLE(QSYS2.ACTIVE_JOB_INFO(DETAILED_INFO => 'WORK')) X
WHERE JOB_STATUS = 'MSGW'
ORDER BY SUBSYSTEM, CPU_TIME DESC
FETCH FIRST ? ROWS ONLY
"""

ASP_INFO_SQL = """
SELECT *
FROM QSYS2.ASP_INFO
ORDER BY ASP_NUMBER
"""

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

LICENSED_PRODUCT_CHECK_SQL = """
SELECT PRODUCT_ID,
       PRODUCT_OPTION,
       RELEASE_LEVEL,
       INSTALLED,
       LOAD_STATE,
       TEXT_DESCRIPTION
FROM QSYS2.SOFTWARE_PRODUCT_INFO
WHERE PRODUCT_ID = ?
ORDER BY PRODUCT_OPTION
"""

QSYSOPR_RECENT_MSGS_SQL = """
SELECT MSG_TIME,
       MSGID,
       MSG_TYPE,
       SEVERITY,
       CAST(MSG_TEXT AS VARCHAR(1024) CCSID 37) AS MSG_TEXT,
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

# -----------------------------------------------------------------------------
# NEW: Library size report (largest libraries)
# Notes:
# - Uses OBJECT_STATISTICS('*ALLSIMPLE','LIB') to list libraries quickly.
# - Uses LIBRARY_INFO per library to compute LIBRARY_SIZE (can be time-consuming).
# -----------------------------------------------------------------------------

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
# TOOLS (Agent-callable)
# =============================================================================

@tool(
    name="get-system-status",
    description="Retrieve overall IBM i system performance statistics (SYSTEM_STATUS).",
)
def get_system_status() -> str:
    return run_select(SYSTEM_STATUS_SQL)


@tool(
    name="get-system-activity",
    description="Retrieve current IBM i activity metrics (SYSTEM_ACTIVITY_INFO), including CPU and jobs.",
)
def get_system_activity() -> str:
    return run_select(SYSTEM_ACTIVITY_SQL)


@tool(
    name="log-performance-metrics",
    description="Save performance metrics to SAMPLE.METRICS for monitoring trend history.",
)
def log_performance_metrics(cpu_usage: float, asp_usage: float) -> str:
    # Intentionally non-SELECT (INSERT) so we call run_sql_statement directly.
    sql = """
        INSERT INTO SAMPLE.METRICS (TIMESTAMP, CPU_PCT, ASP_PCT)
        VALUES (CURRENT_TIMESTAMP, ?, ?)
    """
    return run_sql_statement(sql, parameters=[cpu_usage, asp_usage])


# ---------------- NEW “AMAZING” TOOLS ----------------

@tool(
    name="search-sql-services",
    description="Search IBM i SQL services catalog (QSYS2.SERVICES_INFO) by name/category keyword.",
)
def search_sql_services(keyword: str, limit: int = 50) -> str:
    kw = (keyword or "").strip()
    if not kw:
        raise ValueError("keyword is required")
    lim = _safe_limit(limit, default=50, max_n=200)
    like = f"%{kw}%"
    return run_select(SERVICES_SEARCH_SQL, parameters=[like, like, lim])


@tool(
    name="top-cpu-jobs",
    description="Show top CPU consuming jobs using QSYS2.ACTIVE_JOB_INFO. Optional subsystem/user CSV filters.",
)
def top_cpu_jobs(limit: int = 10, subsystem_csv: str = "", user_csv: str = "") -> str:
    lim = _safe_limit(limit, default=10, max_n=100)
    sbs = _safe_csv_idents(subsystem_csv, what="subsystem list") if subsystem_csv else ""
    usr = _safe_csv_idents(user_csv, what="user list") if user_csv else ""
    return run_select(TOP_CPU_JOBS_SQL, parameters=[sbs, usr, lim])


@tool(
    name="jobs-in-msgw",
    description="List jobs in MSGW (message wait) status, useful for stuck job triage.",
)
def jobs_in_msgw(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=200)
    return run_select(MSGW_JOBS_SQL, parameters=[lim])


@tool(
    name="get-asp-info",
    description="Get ASP (Auxiliary Storage Pool) health/usage information from QSYS2.ASP_INFO.",
)
def get_asp_info() -> str:
    return run_select(ASP_INFO_SQL)


@tool(
    name="disk-hotspots",
    description="Show disks with highest percent used and basic IO counters using QSYS2.SYSDISKSTAT.",
)
def disk_hotspots(limit: int = 10) -> str:
    lim = _safe_limit(limit, default=10, max_n=50)
    return run_select(DISK_HOTSPOTS_SQL, parameters=[lim])


@tool(
    name="netstat-snapshot",
    description="Snapshot of network connections using QSYS2.NETSTAT_INFO (who is connected, idle time, etc.).",
)
def netstat_snapshot(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=200)
    return run_select(NETSTAT_SUMMARY_SQL, parameters=[lim])


@tool(
    name="ptfs-requiring-ipl",
    description="List PTFs that require an IPL to take effect using QSYS2.PTF_INFO.",
)
def ptfs_requiring_ipl(limit: int = 100) -> str:
    lim = _safe_limit(limit, default=100, max_n=500)
    return run_select(PTF_IPL_REQUIRED_SQL, parameters=[lim])


@tool(
    name="check-licensed-product",
    description="Check if a licensed product is installed using QSYS2.SOFTWARE_PRODUCT_INFO (by PRODUCT_ID).",
)
def check_licensed_product(product_id: str) -> str:
    pid = _safe_ident(product_id, what="product_id")
    return run_select(LICENSED_PRODUCT_CHECK_SQL, parameters=[pid])


@tool(
    name="qsysopr-messages",
    description="Fetch recent QSYSOPR messages (non-destructive) using QSYS2.MESSAGE_QUEUE_INFO.",
)
def qsysopr_messages(limit: int = 50) -> str:
    lim = _safe_limit(limit, default=50, max_n=200)
    return run_select(QSYSOPR_RECENT_MSGS_SQL, parameters=[lim])


@tool(
    name="output-queue-hotspots",
    description="Show output queues with the most spooled files using QSYS2.OUTPUT_QUEUE_INFO.",
)
def output_queue_hotspots(limit: int = 20) -> str:
    lim = _safe_limit(limit, default=20, max_n=200)
    return run_select(OUTQ_HOTSPOTS_SQL, parameters=[lim])


@tool(
    name="largest-objects",
    description="Find largest objects in a library using QSYS2.OBJECT_STATISTICS (size + last used).",
)
def largest_objects(library: str, limit: int = 20) -> str:
    lib = _safe_ident(library, what="library")
    lim = _safe_limit(limit, default=20, max_n=200)
    return run_select(LARGEST_OBJECTS_SQL, parameters=[lib, lim])


# -----------------------------------------------------------------------------
# NEW TOOL: Library size report
# -----------------------------------------------------------------------------

@tool(
    name="library-sizes",
    description=(
        "List libraries and their sizes (bytes + GB) using QSYS2.LIBRARY_INFO. "
        "Can be time-consuming on systems with many/large libraries. "
        "Use limit to keep it fast. Optionally exclude system libraries (Q*/#*)."
    ),
)
def library_sizes(limit: int = 50, exclude_system: bool = False) -> str:
    # Library size computation can be expensive; allow larger max but still bounded.
    lim = _safe_limit(limit, default=50, max_n=2000)
    sql = LIBRARY_SIZES_EXCL_SYSTEM_SQL if exclude_system else LIBRARY_SIZES_ALL_SQL
    return run_select(sql, parameters=[lim])


# =============================================================================
# AGENT
# =============================================================================

def build_agent() -> Agent:
    """
    Create the agent with:
    - A Claude model (Anthropic API key must be set)
    - Tools that run fixed SQL (safer than arbitrary SQL execution)
    - Instructions that enforce business-friendly explanations
    """
    model_id = os.getenv("CLAUDE_MODEL_ID", "claude-sonnet-4-5-20250929")

    return Agent(
        name="IBM i Performance & Ops Assistant",
        model=Claude(id=model_id),
        tools=[
            # Original tools
            get_system_status,
            get_system_activity,
            log_performance_metrics,

            # New “amazing” tools
            search_sql_services,
            top_cpu_jobs,
            jobs_in_msgw,
            get_asp_info,
            disk_hotspots,
            netstat_snapshot,
            ptfs_requiring_ipl,
            check_licensed_product,
            qsysopr_messages,
            output_queue_hotspots,
            largest_objects,

            # NEW: Library sizes
            library_sizes,
        ],
        instructions=dedent(
            """
            You are an expert IBM i performance and operations assistant.

            Core rule:
            - Use ONLY the provided tools for system data.
            - Do NOT request or execute arbitrary SQL from the user.

            When troubleshooting:
            - High CPU / slowness → call top-cpu-jobs + get-system-status (optionally get-system-activity).
            - "System feels stuck" / complaints of hangs → call jobs-in-msgw + qsysopr-messages.
            - Disk space alarms / growth → call get-asp-info + disk-hotspots + output-queue-hotspots
              + library-sizes (largest libraries) + largest-objects (largest objects in a suspect library).
            - Connectivity/suspicious connections → call netstat-snapshot.
            - Patch readiness / IPL planning → call ptfs-requiring-ipl.
            - “Is feature X installed?” → call check-licensed-product.
            - “What services exist for X?” → call search-sql-services.
            - “Largest library / library sizes” → call library-sizes (limit=1 for largest).

            Output requirements:
            - Summarize key findings in business-friendly language.
            - Highlight concerning values (e.g., high CPU, many MSGW jobs, high disk % used, many spooled files).
            - If a metric is not present in tool output, say so and suggest the closest available metric.

            Style:
            - Use Markdown formatting.
            - Provide a short "Summary" followed by "Details" and "Next actions".
            """
        ).strip(),
        markdown=True,
    )


# =============================================================================
# MAIN LOOP
# =============================================================================

def main():
    # Fail fast if required env vars are not present
    _ = get_ibmi_credentials()
    _ = _require_env("ANTHROPIC_API_KEY")

    agent = build_agent()

    print("\n✅ IBM i Performance & Ops Agent is ready.")
    print("Try questions like:")
    print(" - 'What are the top CPU jobs right now?'")
    print(" - 'Any jobs stuck in MSGW?'")
    print(" - 'Show ASP info and disk hotspots'")
    print(" - 'Any PTFs requiring IPL?'")
    print(" - 'Recent QSYSOPR messages'")
    print(" - 'Which output queues have the most spool files?'")
    print(" - 'Largest objects in library MYLIB'")
    print(" - 'Search IBM i SQL services for security'")
    print(" - 'Which is the largest library on the system?'")
    print(" - 'Show top 25 largest libraries (exclude system libraries)'")
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