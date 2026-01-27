# new_IBMi_agent.py - Dynamic Text-to-SQL IBM i Agent
# A simplified architecture using 4 tools instead of 73
# The LLM discovers services, learns schemas, and generates SQL dynamically

import os
import re
import sys
import json
from textwrap import dedent
from typing import Any, Dict, Optional, List, Tuple

# Fix Windows console encoding for emojis and markdown
if sys.platform == "win32":
    try:
        # Set console to UTF-8 mode for both input and output
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleOutputCP(65001)  # UTF-8 output
        kernel32.SetConsoleCP(65001)       # UTF-8 input
        
        # Also configure Python's stdout/stderr encoding
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except:
        pass  # Fallback to default encoding

from dotenv import load_dotenv
from mapepire_python import connect
from pep249 import QueryParameters

from agno.agent import Agent, RunEvent, RunOutputEvent
from agno.models.openrouter import OpenRouter
from agno.tools import tool

# Import rich for markdown rendering and styled output
try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich import box
    _console = Console()
    _has_rich = True
except ImportError:
    _has_rich = False
    _console = None

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
            f"Set it in your shell or in a .env file."
        )
    return value


def get_ibmi_credentials() -> Dict[str, Any]:
    """Mapepire connection details. Default port is 8076."""
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


# =============================================================================
# CONNECTION POOLING & RESULT HANDLING
# =============================================================================

import time as _time

_connection_pool: List[Any] = []
_MAX_POOL_SIZE = int(os.getenv("IBMI_POOL_SIZE", "5"))
_MAX_RETRIES = 3
_RETRY_DELAY_BASE = 2

MAX_RESULT_ROWS = int(os.getenv("MAX_RESULT_ROWS", "500"))
MAX_RESULT_BYTES = int(os.getenv("MAX_RESULT_BYTES", "500000"))  # Increased to 500KB to prevent truncation


def _get_pooled_connection() -> Any:
    """Get a connection with retry logic and exponential backoff."""
    creds = get_ibmi_credentials()
    for attempt in range(_MAX_RETRIES):
        try:
            if _connection_pool:
                conn = _connection_pool.pop()
                return conn
            return connect(creds)
        except Exception as e:
            if attempt == _MAX_RETRIES - 1:
                raise
            delay = _RETRY_DELAY_BASE ** attempt
            print(f"[CONNECTION] Retry {attempt + 1}/{_MAX_RETRIES} after {delay}s: {e}", file=sys.stderr)
            _time.sleep(delay)
    return connect(creds)


def _return_connection_to_pool(conn: Any) -> None:
    """Return a connection to the pool if there's room."""
    if len(_connection_pool) < _MAX_POOL_SIZE:
        _connection_pool.append(conn)
    else:
        try:
            conn.close()
        except Exception:
            pass


def format_result(result: Any) -> str:
    """Format results as readable JSON with size limits."""
    try:
        truncated = False
        if isinstance(result, list) and len(result) > MAX_RESULT_ROWS:
            result = result[:MAX_RESULT_ROWS]
            truncated = True

        output = json.dumps(result, indent=2, default=str)

        if len(output) > MAX_RESULT_BYTES:
            output = output[:MAX_RESULT_BYTES] + "\n... (truncated due to size)"
            truncated = True
        elif truncated:
            output += f"\n... (truncated to {MAX_RESULT_ROWS} rows)"

        return output
    except Exception:
        return str(result)


def run_sql(sql: str, parameters: Optional[QueryParameters] = None) -> str:
    """Execute SQL and return formatted results."""
    creds = get_ibmi_credentials()
    with connect(creds) as conn:
        with conn.execute(sql, parameters=parameters) as cur:
            if getattr(cur, "has_results", False):
                raw = cur.fetchall()
                if isinstance(raw, dict) and "data" in raw:
                    return format_result(raw["data"])
                return format_result(raw)
            return "SQL executed successfully. No results returned."


# =============================================================================
# SAFETY VALIDATION LAYER
# =============================================================================

_SAFE_IDENT = re.compile(r"^[A-Z0-9_#$@]{1,128}$", re.IGNORECASE)

_FORBIDDEN_SQL_TOKENS = re.compile(
    r"(\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bMERGE\b|\bDROP\b|\bALTER\b|\bCREATE\b|\bCALL\b|\bGRANT\b|\bREVOKE\b|\bRUN\b|\bCL:\b|\bQCMDEXC\b)",
    re.IGNORECASE,
)

# Only these schemas are allowed in queries
_ALLOWED_SCHEMAS = {"QSYS2", "SYSTOOLS", "SYSIBM", "QSYS", "INFORMATION_SCHEMA"}

# Expand with user-defined schemas from environment
user_schemas = os.getenv("ALLOWED_USER_SCHEMAS", "").strip()
if user_schemas:
    user_schemas_list = [s.strip().upper() for s in user_schemas.split(",") if s.strip()]
    _ALLOWED_SCHEMAS.update(user_schemas_list)
    print(f"[SECURITY] User schemas enabled: {', '.join(user_schemas_list)}", file=sys.stderr)


def _safe_ident(value: str, what: str = "identifier") -> str:
    """Validate and normalize an identifier."""
    v = (value or "").strip()
    if not v or not _SAFE_IDENT.match(v):
        raise ValueError(f"Invalid {what}: {value!r}")
    return v.upper()


def _safe_limit(n: int, default: int = 50, max_n: int = 500) -> int:
    """Validate and constrain a numeric limit."""
    try:
        n = int(n)
    except Exception:
        return default
    return max(1, min(n, max_n))


def _validate_select_query(sql: str) -> None:
    """
    Validate that a SQL query is safe to execute.
    Raises ValueError if the query violates safety rules.
    """
    s = (sql or "").strip()

    if not s:
        raise ValueError("Empty SQL is not allowed.")

    # Must start with SELECT or WITH
    head = s.lstrip().upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise ValueError("Only SELECT/WITH statements are allowed.")

    # No multiple statements
    if ";" in s:
        raise ValueError("Multiple statements are not allowed (no semicolons).")

    # No SQL comments (can hide malicious code)
    if "--" in s or "/*" in s:
        raise ValueError("SQL comments are not allowed for security.")

    # No forbidden operations
    if _FORBIDDEN_SQL_TOKENS.search(s):
        raise ValueError("Forbidden SQL operation detected. Only read-only queries are allowed.")

    # Schema whitelist check
    schema_refs = set(re.findall(r"\b([A-Z0-9_#$@]{1,128})\s*\.", s.upper()))
    for sch in schema_refs:
        # Skip SQL keywords that look like schema refs
        if sch in {"TABLE", "VALUES", "LATERAL", "CAST", "TRIM", "COALESCE", "CASE"}:
            continue
        if sch not in _ALLOWED_SCHEMAS:
            raise ValueError(
                f"Query references non-allowed schema '{sch}'. "
                f"Allowed schemas: {sorted(_ALLOWED_SCHEMAS)}"
            )


# =============================================================================
# CORE TOOLS (4 tools instead of 73)
# =============================================================================

def _build_service_search_conditions(search_term: str) -> Tuple[str, List[str]]:
    """
    Build WHERE conditions for multi-word search.
    Splits 'system status' into ['system', 'status'] and matches ANY word.
    Also searches in SERVICE_NAME, SERVICE_CATEGORY, and EXAMPLE_SQL.
    """
    words = [w.strip().upper() for w in (search_term or "").split() if w.strip()]

    if not words:
        return "1=1", []  # No filter - return all

    conditions = []
    params = []
    for word in words:
        # Each word can match service name, category, or example SQL
        conditions.append("""(
            UPPER(SERVICE_NAME) LIKE '%' || ? || '%'
            OR UPPER(SERVICE_CATEGORY) LIKE '%' || ? || '%'
            OR UPPER(CAST(EXAMPLE_SQL AS VARCHAR(4000))) LIKE '%' || ? || '%'
        )""")
        params.extend([word, word, word])

    # Join with OR - match ANY word (more lenient search)
    return "(" + " OR ".join(conditions) + ")", params


@tool(name="discover-services", description="Search IBM i Services catalog. Use SINGLE KEYWORDS like 'JOB' or 'CERTIFICATE', not phrases. Only call this if the query doesn't match the Quick Reference in your instructions.")
def discover_services(
    search_term: str = "",
    category: str = "",
    limit: int = 30
) -> str:
    """
    Query QSYS2.SERVICES_INFO to discover available IBM i services.

    Parameters:
    - search_term: Keyword(s) to search (e.g., "JOB", "CPU", "USER", "CERTIFICATE")
                   Multi-word searches like "system status" will match ANY word.
    - category: Filter by category (e.g., "WORK_MANAGEMENT", "SECURITY", "PERFORMANCE")
    - limit: Maximum results to return (default 30)

    TIP: Use SINGLE keywords for best results. "JOB" works better than "active jobs".
    """
    try:
        # Build dynamic WHERE clause with word splitting
        where_clause, params = _build_service_search_conditions(search_term)

        # Add category filter if provided
        cat = (category or "").strip().upper()
        if cat:
            where_clause = f"{where_clause} AND UPPER(SERVICE_CATEGORY) LIKE '%' || ? || '%'"
            params.append(cat)

        # Build final SQL
        sql = f"""
        SELECT
            SERVICE_SCHEMA_NAME,
            SERVICE_NAME,
            SERVICE_CATEGORY,
            SQL_OBJECT_TYPE,
            EARLIEST_POSSIBLE_RELEASE,
            CAST(EXAMPLE_SQL AS VARCHAR(2000)) AS EXAMPLE_SQL
        FROM QSYS2.SERVICES_INFO
        WHERE {where_clause}
        ORDER BY SERVICE_CATEGORY, SERVICE_NAME
        FETCH FIRST ? ROWS ONLY
        """
        params.append(_safe_limit(limit, default=30, max_n=100))

        return run_sql(sql, parameters=params)
    except Exception as e:
        return f"ERROR discovering services: {type(e).__name__}: {e}"


GET_TABLE_SCHEMA_SQL = """
SELECT
    COLUMN_NAME,
    DATA_TYPE,
    LENGTH,
    NUMERIC_SCALE,
    IS_NULLABLE,
    HAS_DEFAULT,
    COLUMN_TEXT
FROM QSYS2.SYSCOLUMNS
WHERE TABLE_SCHEMA = ?
  AND TABLE_NAME = ?
ORDER BY ORDINAL_POSITION
"""


@tool(name="get-table-schema", description="Get column definitions for a table, view, or service. Use this after discover-services to learn what columns are available.")
def get_table_schema(
    schema: str,
    table_name: str
) -> str:
    """
    Query QSYS2.SYSCOLUMNS to get column metadata for any table/view/function.

    Parameters:
    - schema: Schema name (usually QSYS2 for IBM i services)
    - table_name: Table, view, or function name (e.g., ACTIVE_JOB_INFO, SYSTEM_STATUS)

    Returns column name, data type, length, nullability, and description.
    Use this information to write correct SELECT queries.
    """
    try:
        sch = _safe_ident(schema, what="schema")
        tbl = _safe_ident(table_name, what="table_name")

        return run_sql(GET_TABLE_SCHEMA_SQL, parameters=[sch, tbl])
    except ValueError as e:
        return f"VALIDATION_ERROR: {e}"
    except Exception as e:
        return f"ERROR getting schema: {type(e).__name__}: {e}"


@tool(name="execute-sql", description="Execute a validated read-only SQL query against IBM i. The query must be a SELECT or WITH statement.")
def execute_sql(
    sql: str,
    limit_override: int = 100
) -> str:
    """
    Execute a dynamically generated SQL query with full safety validation.

    Parameters:
    - sql: The SELECT/WITH query to execute
    - limit_override: Row limit to apply if FETCH FIRST not present (default 100)

    SAFETY RULES (automatically enforced):
    - ONLY SELECT/WITH statements allowed
    - No semicolons (single statement only)
    - No INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/CALL
    - Only allowed schemas: QSYS2, SYSTOOLS, SYSIBM, QSYS, INFORMATION_SCHEMA
    - No SQL comments (-- or /* */)

    If the query fails, the error message is returned to help you correct it.
    Common issues: wrong column names, missing parameters for table functions, syntax errors.
    """
    try:
        # Validate the SQL first
        _validate_select_query(sql)

        # Apply row limit if not present
        sql_upper = sql.upper()
        if "FETCH FIRST" not in sql_upper and "LIMIT" not in sql_upper:
            # Remove trailing whitespace and add limit
            sql = sql.rstrip()
            if sql.endswith(";"):
                sql = sql[:-1]
            lim = _safe_limit(limit_override, default=100, max_n=500)
            sql = f"{sql}\nFETCH FIRST {lim} ROWS ONLY"

        # Execute and return results
        return run_sql(sql)

    except ValueError as e:
        return f"""VALIDATION_ERROR: {e}

Your SQL query violated safety rules. Please revise:
- Ensure query starts with SELECT or WITH
- Remove any semicolons
- Remove any SQL comments (-- or /* */)
- Only reference allowed schemas: {sorted(_ALLOWED_SCHEMAS)}
- Do not use INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, or CALL"""

    except Exception as e:
        error_msg = str(e)
        return f"""SQL_ERROR: {type(e).__name__}
Error Message: {error_msg}

Failed SQL:
{sql}

Common Fixes:
- Check column names match the schema from get-table-schema
- For TABLE FUNCTIONS, ensure required parameters are provided
- Check syntax of WHERE, ORDER BY, GROUP BY clauses
- Verify string literals use single quotes ('value')
- Check that table/view exists with discover-services"""


@tool(name="get-sample-data", description="Preview a few rows from a table or view to understand data patterns. Useful before writing complex queries.")
def get_sample_data(
    schema: str,
    table_name: str,
    limit: int = 5
) -> str:
    """
    Fetch sample rows to understand data format and values.

    Parameters:
    - schema: Schema name (usually QSYS2)
    - table_name: Table or view name
    - limit: Number of rows to return (default 5, max 20)

    Note: This works for VIEWs and TABLEs, not for TABLE FUNCTIONS.
    For table functions, use execute-sql with the proper function call syntax.
    """
    try:
        sch = _safe_ident(schema, what="schema")
        tbl = _safe_ident(table_name, what="table_name")
        lim = _safe_limit(limit, default=5, max_n=20)

        if sch not in _ALLOWED_SCHEMAS:
            return f"ERROR: Schema '{sch}' not in allowed list: {sorted(_ALLOWED_SCHEMAS)}"

        sql = f"SELECT * FROM {sch}.{tbl} FETCH FIRST {lim} ROWS ONLY"
        return run_sql(sql)

    except ValueError as e:
        return f"VALIDATION_ERROR: {e}"
    except Exception as e:
        # Provide helpful error for table functions
        error_msg = str(e)
        if "not found" in error_msg.lower() or "not valid" in error_msg.lower():
            return f"""ERROR: {error_msg}

This might be a TABLE FUNCTION rather than a VIEW/TABLE.
For table functions, use execute-sql with syntax like:
  SELECT * FROM TABLE(QSYS2.{table_name}(...)) AS X FETCH FIRST 5 ROWS ONLY

Check the EXAMPLE_SQL from discover-services for the correct syntax."""
        return f"ERROR: {type(e).__name__}: {e}"


@tool(name="list-library-objects", description="List all objects (tables, physical files, programs) in a user library. Use this for 'files in library', 'tables in schema', or 'library contents' queries. Much faster than multiple individual queries.")
def list_library_objects(
    library: str,
    object_type: str = "*FILE"
) -> str:
    """
    List objects in a library using QSYS2.OBJECT_STATISTICS.
    This is the FASTEST way to get library contents in a single query.

    Parameters:
    - library: Library name (e.g., DHEERAJ, MYLIB, PRODLIB)
    - object_type: Object type filter:
        *ALL = All objects
        *FILE = All files (physical + logical)
        *PGM = Programs
        *SRVPGM = Service programs
        *DTAARA = Data areas

    Returns: Object name, type, size, description, creation date, last used date

    TIP: Use *FILE for physical files in a library, then use execute-sql with
    QSYS2.SYSCOLUMNS to get column details for specific tables.
    """
    try:
        lib = _safe_ident(library, what="library")

        # Validate object type (allow common IBM i object types)
        valid_types = {"*ALL", "*FILE", "*PGM", "*SRVPGM", "*DTAARA", "*DTAQ", "*OUTQ", "*JOBD", "*MSGQ"}
        obj_type = (object_type or "*FILE").upper().strip()
        if obj_type not in valid_types:
            obj_type = "*FILE"  # Default to files

        sql = f"""
        SELECT
            OBJNAME AS OBJECT_NAME,
            OBJTYPE AS TYPE,
            OBJSIZE AS SIZE_BYTES,
            OBJTEXT AS DESCRIPTION,
            OBJCREATED AS CREATED,
            LAST_USED_TIMESTAMP AS LAST_USED,
            OBJOWNER AS OWNER
        FROM TABLE(QSYS2.OBJECT_STATISTICS('{lib}', '{obj_type}')) AS X
        ORDER BY OBJNAME
        FETCH FIRST 100 ROWS ONLY
        """
        return run_sql(sql)

    except ValueError as e:
        return f"VALIDATION_ERROR: {e}"
    except Exception as e:
        return f"ERROR listing library objects: {type(e).__name__}: {e}"


@tool(name="read-source-member", description="Read actual source code from a source physical file member. Use this to examine RPG, CL, DDS, or other source code.")
def read_source_member(
    library: str,
    source_file: str,
    member_name: str,
    start_line: int = 1,
    num_lines: int = 100
) -> str:
    """
    Read source code lines from a source physical file member.

    Parameters:
    - library: Library containing the source file (e.g., 'DHEERAJ')
    - source_file: Source physical file name (e.g., 'QRPGLESRC', 'QCLLESRC')
    - member_name: Member name to read (e.g., 'ADMINM', 'LOGINM')
    - start_line: Starting line number (default 1)
    - num_lines: Number of lines to read (default 100, max 500)

    Returns source code with line numbers, date changed, and source lines.

    Example: read_source_member("DHEERAJ", "QRPGLESRC", "ADMINM", 1, 50)
    """
    try:
        lib = _safe_ident(library, what="library")
        srcfile = _safe_ident(source_file, what="source_file")
        member = _safe_ident(member_name, what="member")

        start = max(1, int(start_line))
        limit = _safe_limit(num_lines, default=100, max_n=500)

        # Query source file using qualified name with member parameter
        sql = f"""
        SELECT
            SRCSEQ AS LINE_NUM,
            CAST(SRCDTA AS VARCHAR(250)) AS SOURCE_LINE,
            CAST(SRCDAT AS VARCHAR(10)) AS DATE_CHANGED
        FROM {lib}.{srcfile}({member})
        WHERE SRCSEQ >= {start}
        ORDER BY SRCSEQ
        FETCH FIRST {limit} ROWS ONLY
        """

        return run_sql(sql)

    except ValueError as e:
        return f"VALIDATION_ERROR: {e}"
    except Exception as e:
        # Provide helpful guidance
        error_msg = str(e)
        if "not found" in error_msg.lower() or "not valid" in error_msg.lower():
            return f"""ERROR: Source member '{member_name}' not found in {library}/{source_file}.

Troubleshooting steps:
1. Verify the source file exists: list-library-objects(library="{library}", object_type="*FILE")
2. List available members: execute-sql with QSYS2.SYSPARTITIONSTAT
   Example SQL: SELECT SYSTEM_TABLE_MEMBER FROM QSYS2.SYSPARTITIONSTAT
   WHERE SYSTEM_TABLE_SCHEMA='{library}' AND SYSTEM_TABLE_NAME='{source_file}'

Common source files:
- QRPGLESRC: RPG/RPGLE programs
- QCLLESRC: CL programs
- QDDSSRC: DDS files
- QSQLSRC: SQL scripts"""
        return f"ERROR reading source member: {type(e).__name__}: {e}"


# =============================================================================
# STREAMING EVENT HANDLER
# =============================================================================

import time
from threading import Thread

# Global state for thinking indicator and response buffering
_thinking_active = False
_thinking_thread = None
_in_final_response = False
_response_buffer = []  # Buffer for final response
_query_start_time = None  # Track query start time for response time
_tool_call_count = 0  # Track number of tool calls
_seen_tool_calls = False  # Track if we've seen any tool calls yet

def _is_final_response_chunk(chunk: RunOutputEvent) -> bool:
    """Best-effort detection of whether a run_content chunk belongs to the final answer.

    Agno model adapters sometimes stream the final answer without tool calls,
    or they emit it in small chunks (<50 chars). The older heuristic
    ("tool_call_count > 0 and len(content) > 50") can fail and result in:
    - no buffering
    - no rich markdown render
    - no green bordered panel
    """
    try:
        # Prefer explicit signal if provided
        if hasattr(chunk, "is_final") and bool(getattr(chunk, "is_final")):
            return True
        # Some event payloads include a phase/type field
        if hasattr(chunk, "phase") and str(getattr(chunk, "phase")).lower() in {"final", "answer"}:
            return True
        if hasattr(chunk, "content_type") and str(getattr(chunk, "content_type")).lower() in {"final", "answer"}:
            return True
    except Exception:
        pass

    # If any tool call happened, the subsequent assistant content is typically the final answer.
    if _tool_call_count > 0:
        return True

    # Otherwise, treat content that looks like formatted markdown as a final answer.
    content = getattr(chunk, "content", "") or ""
    c = content.lstrip()
    if not c:
        return False

    markdownish = (
        c.startswith("#")
        or c.startswith("-")
        or c.startswith("*")
        or c.startswith("```")
        or c.startswith("|")
        or re.match(r"^\d+\.", c) is not None
        or "\n##" in content
        or "\n- " in content
        or "```" in content
    )
    return bool(markdownish)

def show_thinking_indicator():
    """Display animated thinking indicator while waiting."""
    global _thinking_active
    symbols = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    idx = 0
    while _thinking_active:
        try:
            safe_print(f"\r💭 Thinking {symbols[idx % len(symbols)]}  ", end="", flush=True)
        except:
            # Fallback for encoding issues
            print(f"\r[THINKING] {symbols[idx % len(symbols)]}  ", end="", flush=True)
        idx += 1
        time.sleep(0.1)
    # Clear the thinking line
    print("\r" + " " * 30 + "\r", end="", flush=True)

def start_thinking():
    """Start thinking indicator in background."""
    global _thinking_active, _thinking_thread
    if not _thinking_active:
        _thinking_active = True
        _thinking_thread = Thread(target=show_thinking_indicator, daemon=True)
        _thinking_thread.start()

def stop_thinking():
    """Stop thinking indicator."""
    global _thinking_active
    if _thinking_active:
        _thinking_active = False
        time.sleep(0.15)  # Let thread finish

def safe_print(text: str, **kwargs) -> None:
    """Print text with fallback for encoding errors (Windows compatibility)."""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        # Last resort: encode as ASCII, replacing only problematic chars
        # This preserves markdown formatting as much as possible
        text_ascii = text.encode('ascii', errors='replace').decode('ascii')
        print(text_ascii, **kwargs)

def handle_agent_event(chunk: RunOutputEvent) -> None:
    """
    Process and display streaming events from agent execution.
    Shows real-time progress: tools being called, SQL execution, results streaming.
    """
    global _in_final_response, _response_buffer, _query_start_time, _tool_call_count, _seen_tool_calls

    # Agent lifecycle events
    if chunk.event == RunEvent.run_started:
        _query_start_time = time.time()  # Start timing
        _tool_call_count = 0  # Reset tool count
        _seen_tool_calls = False  # Reset tool call tracking
        _response_buffer.clear()
        # Track final-only content as a safety net if buffering heuristics fail.
        handle_agent_event._last_final_content = ""
        safe_print("\n🤖 [AGENT] Starting to process your query...\n")
        start_thinking()  # Start thinking indicator

    elif chunk.event == RunEvent.run_completed:
        stop_thinking()  # Ensure thinking indicator is stopped

        # Calculate response time
        response_time = time.time() - _query_start_time if _query_start_time else 0

        # Print complete buffered response with markdown rendering in green-bordered panel
        # If buffering didn't trigger (heuristic miss), fall back to last content seen.
        full_response = "".join(_response_buffer).strip()
        if not full_response and hasattr(handle_agent_event, "_last_final_content"):
            full_response = str(getattr(handle_agent_event, "_last_final_content") or "").strip()

        if full_response:
            # Use rich Console with styled Panel for beautiful output
            if _has_rich and _console:
                try:
                    # Create markdown object
                    md = Markdown(full_response)

                    # Wrap in a HEAVY green-bordered panel for visual distinction
                    panel = Panel(
                        md,
                        title="[bold white]📊 AGENT ANALYSIS[/bold white]",
                        border_style="green",
                        box=box.HEAVY,  # Thicker border
                        padding=(1, 2)
                    )

                    print()  # Add spacing before panel
                    _console.print(panel)

                except Exception as e:
                    # Fallback to plain print if markdown rendering fails
                    safe_print(f"\n[DEBUG] Markdown rendering failed: {e}")
                    print(full_response, flush=True)
            else:
                # Fallback: plain print without markdown rendering
                try:
                    print(full_response, flush=True)
                except UnicodeEncodeError:
                    safe_response = full_response.encode('ascii', errors='replace').decode('ascii')
                    print(safe_response, flush=True)

        # Reset state for next query
        _in_final_response = False
        _response_buffer.clear()
        handle_agent_event._last_final_content = ""

        # Show completion message with timing and tool count
        safe_print(f"\n✅ [AGENT] Query processing complete! (⏱️ {response_time:.2f}s, 🔧 {_tool_call_count} tool calls)\n")

    # Tool execution events
    elif chunk.event == RunEvent.tool_call_started:
        stop_thinking()  # Stop thinking while showing tool info
        _tool_call_count += 1  # Increment tool call counter
        # Mark that we're currently in a tool call (for content routing)
        _seen_tool_calls = True

        tool = chunk.tool
        tool_name = tool.tool_name if tool else "unknown"

        safe_print(f"\n🔧 [TOOL] Calling: {tool_name}")

        # Show specific details based on tool
        # Try multiple attribute names for tool arguments
        tool_input = {}
        if tool:
            if hasattr(tool, 'tool_args'):
                tool_input = tool.tool_args or {}
            elif hasattr(tool, 'arguments'):
                tool_input = tool.arguments or {}
            elif hasattr(chunk, 'tool_call_args'):
                tool_input = chunk.tool_call_args or {}
            elif hasattr(chunk, 'args'):
                tool_input = chunk.args or {}

        if tool_input:
            if tool_name == "discover-services":
                search = tool_input.get("search_term", "")
                if search:
                    safe_print(f"   └─ Searching for: '{search}'")

            elif tool_name == "get-table-schema":
                schema = tool_input.get("schema", "")
                table = tool_input.get("table_name", "")
                if schema or table:
                    safe_print(f"   └─ Schema: {schema}.{table}")

            elif tool_name == "execute-sql":
                sql = tool_input.get("sql", "")
                if sql:
                    # Show first 100 chars of SQL (user preference)
                    sql_preview = sql[:100] + "..." if len(sql) > 100 else sql
                    # Clean up whitespace for single-line display
                    sql_preview = " ".join(sql_preview.split())
                    safe_print(f"   └─ SQL: {sql_preview}")

            elif tool_name == "get-sample-data":
                schema = tool_input.get("schema", "")
                table = tool_input.get("table_name", "")
                limit = tool_input.get("limit", 5)
                if schema or table:
                    safe_print(f"   └─ Fetching {limit} rows from {schema}.{table}")

            elif tool_name == "list-library-objects":
                library = tool_input.get("library", "")
                obj_type = tool_input.get("object_type", "*FILE")
                if library:
                    safe_print(f"   └─ Library: {library} (Type: {obj_type})")

    elif chunk.event == RunEvent.tool_call_completed:
        tool = chunk.tool
        tool_name = tool.tool_name if tool else "unknown"

        # Check for errors
        if hasattr(chunk, 'error') and chunk.error:
            safe_print(f"   └─ ❌ Error: {chunk.error}")
        else:
            # Try to get result info
            result_preview = ""
            if hasattr(chunk, 'result'):
                result_preview = str(chunk.result) if chunk.result else ""
            elif tool and hasattr(tool, 'result'):
                result_preview = str(tool.result) if tool.result else ""

            if isinstance(result_preview, str) and len(result_preview) > 100:
                # Count rows in JSON result
                try:
                    data = json.loads(result_preview)
                    if isinstance(data, list):
                        safe_print(f"   └─ ✓ Returned {len(data)} rows")
                    else:
                        safe_print(f"   └─ ✓ Complete")
                except:
                    safe_print(f"   └─ ✓ Complete")
            else:
                safe_print(f"   └─ ✓ Complete")

        # Reset flag so next thinking text will be shown (before next tool)
        _seen_tool_calls = False
        # Resume thinking indicator after tool completion
        start_thinking()

    # LLM text streaming - Show thinking text, buffer final response
    elif chunk.event == RunEvent.run_content:
        content = chunk.content if hasattr(chunk, 'content') else ""
        if content:
            # If we're not in final response phase, show thinking text immediately
            if not _in_final_response:
                # Check if this looks like the start of final response
                if _is_final_response_chunk(chunk):
                    _in_final_response = True
                    _response_buffer.append(content)
                    handle_agent_event._last_final_content = (getattr(handle_agent_event, "_last_final_content", "") or "") + content
                else:
                    # This is thinking text - show it immediately
                    stop_thinking()  # Stop spinner to show thinking text
                    safe_print(content, end="", flush=True)
            else:
                # Already in final response - continue buffering
                _response_buffer.append(content)
                handle_agent_event._last_final_content = (getattr(handle_agent_event, "_last_final_content", "") or "") + content

    # Reasoning/planning events (if available)
    elif chunk.event == RunEvent.reasoning_step:
        reasoning = chunk.reasoning_content if hasattr(chunk, 'reasoning_content') else ""
        if reasoning:
            reasoning_preview = reasoning[:100] + "..." if len(reasoning) > 100 else reasoning
            safe_print(f"💭 [THINKING] {reasoning_preview}")


# =============================================================================
# AGENT CONFIGURATION
# =============================================================================

AGENT_INSTRUCTIONS = dedent("""
    You are an expert IBM i system assistant that generates SQL dynamically.

    ## CRITICAL: Use Quick Reference FIRST - Skip Discovery When Possible!

    For common queries, use these services DIRECTLY without calling discover-services.
    Just call get-table-schema for columns, then execute-sql with your query.

    ### Quick Reference - Common Services

    | Keywords in Question | Service Name | SQL Syntax |
    |---------------------|--------------|------------|
    | system status, cpu %, memory, total jobs | SYSTEM_STATUS | SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS()) AS X |
    | top cpu jobs, active jobs, running jobs | ACTIVE_JOB_INFO | SELECT * FROM TABLE(QSYS2.ACTIVE_JOB_INFO(DETAILED_INFO=>'ALL')) AS X |
    | listen ports, netstat, tcp, connections | NETSTAT_INFO | SELECT * FROM QSYS2.NETSTAT_INFO WHERE TCP_STATE = 'LISTEN' |
    | users, profiles, authorities | USER_INFO | SELECT * FROM QSYS2.USER_INFO |
    | certificates, ssl, expiring, https | CERTIFICATE_INFO | SELECT * FROM TABLE(QSYS2.CERTIFICATE_INFO('*SYSTEM','*ALL')) AS X |
    | ptf, patches, fixes, updates | PTF_INFO | SELECT * FROM TABLE(QSYS2.PTF_INFO()) AS X |
    | disk, asp, storage, disk space | ASP_INFO | SELECT * FROM QSYS2.ASP_INFO |
    | messages, qsysopr, msgq | MESSAGE_QUEUE_INFO | SELECT * FROM TABLE(QSYS2.MESSAGE_QUEUE_INFO('QSYSOPR','QSYS')) AS X |
    | plan cache, sql performance, slow queries | PLAN_CACHE_EVENT_INFO | SELECT * FROM TABLE(QSYS2.PLAN_CACHE_EVENT_INFO()) AS X |
    | journals, journal receivers | JOURNAL_INFO | SELECT * FROM TABLE(QSYS2.JOURNAL_INFO(JOURNAL_LIBRARY=>'*ALL')) AS X |
    | job queues, batch jobs waiting | JOB_QUEUE_INFO | SELECT * FROM QSYS2.JOB_QUEUE_INFO |
    | subsystems, sbsd | SUBSYSTEM_INFO | SELECT * FROM QSYS2.SUBSYSTEM_INFO |
    | system values, sysval | SYSTEM_VALUE_INFO | SELECT * FROM QSYS2.SYSTEM_VALUE_INFO |
    | locks, object locks, waiting | OBJECT_LOCK_INFO | SELECT * FROM QSYS2.OBJECT_LOCK_INFO |
    | library, libraries, library list | LIBRARY_INFO | SELECT * FROM QSYS2.LIBRARY_INFO |

    ### Quick Reference - Library & Catalog Services (for user schemas)

    | Keywords in Question | Service/Table | SQL Syntax |
    |---------------------|---------------|------------|
    | tables in library, physical files, files in library | SYSTABLES | SELECT TABLE_NAME, TABLE_TEXT, COLUMN_COUNT, ROW_LENGTH FROM QSYS2.SYSTABLES WHERE SYSTEM_TABLE_SCHEMA = 'LIBNAME' |
    | table columns, describe table, table structure | SYSCOLUMNS | SELECT COLUMN_NAME, DATA_TYPE, LENGTH, COLUMN_TEXT FROM QSYS2.SYSCOLUMNS WHERE TABLE_SCHEMA = 'LIBNAME' AND TABLE_NAME = 'TABLENAME' |
    | objects in library, library contents, file sizes | OBJECT_STATISTICS | SELECT * FROM TABLE(QSYS2.OBJECT_STATISTICS('LIBNAME', '*ALL')) AS X |
    | physical files only | OBJECT_STATISTICS | SELECT * FROM TABLE(QSYS2.OBJECT_STATISTICS('LIBNAME', '*FILE')) AS X |

    ### Quick Reference - Source Code Analysis

    | Keywords in Question | Tool/Service | When to Use |
    |---------------------|--------------|-------------|
    | read source, show source code, examine RPG/CL | read-source-member | Direct access to source code lines from source physical files (QRPGLESRC, QCLLESRC, etc.) |
    | list source members, members in source file | SYSPARTITIONSTAT | Get list of members with metadata: SELECT SYSTEM_TABLE_MEMBER, PARTITION_SIZE FROM QSYS2.SYSPARTITIONSTAT WHERE SYSTEM_TABLE_SCHEMA='LIBNAME' AND SYSTEM_TABLE_NAME='QRPGLESRC' |
    | source member details, line count, last changed | SYSPARTITIONSTAT | Metadata only (no source code): SELECT SYSTEM_TABLE_MEMBER, PARTITION_SIZE, LAST_CHANGE_TIMESTAMP FROM QSYS2.SYSPARTITIONSTAT |

    **IMPORTANT**: Use read-source-member tool for reading actual source code. This is far more efficient than trying multiple approaches!

    ## IMPORTANT: Batching Rules for Multi-Table Queries

    When analyzing multiple tables in a library (e.g., "insights of files in X library"):
    1. **First**, list ALL tables with a SINGLE SYSTABLES or OBJECT_STATISTICS query
    2. **Then**, get column info for only 2-3 KEY tables with SYSCOLUMNS (not all!)
    3. **Finally**, sample data from only 2-3 REPRESENTATIVE tables (not every table!)
    4. **NEVER** call get-sample-data more than 3 times in a single response
    5. Summarize patterns across tables rather than examining each individually

    ## When to Call discover-services

    ONLY call discover-services if:
    1. The query doesn't match any Quick Reference above
    2. You need a specific/obscure service not listed
    3. You're unsure which service to use

    When searching, use SINGLE KEYWORDS like "JOB" or "SECURITY", not phrases.

    ## Optimized Workflow

    1. **Check Quick Reference** → If keywords match, skip to step 3!
    2. **(Only if needed)** Call discover-services with single keyword
    3. Always Call get-table-schema to get proper column names
    4. Call execute-sql with your query
    5. Search for helpful resources on web where required (prefer IBM i docs)                        
    6. Analyze results and respond

    ## SQL Generation Rules

    **For TABLE FUNCTIONS** (most IBM i services):
    ```sql
    SELECT column1, column2
    FROM TABLE(QSYS2.SERVICE_NAME(PARAM => 'value')) AS X
    WHERE condition
    ORDER BY column1 DESC
    FETCH FIRST 50 ROWS ONLY
    ```

    **For VIEWs**:
    ```sql
    SELECT column1, column2
    FROM QSYS2.VIEW_NAME
    WHERE condition
    ORDER BY column1
    FETCH FIRST 100 ROWS ONLY
    ```

    ## Self-Correction

    If you get an error, READ THE ERROR MESSAGE:
    - "column not found" → Re-check schema with get-table-schema
    - "not a valid table" → It's a TABLE FUNCTION, use TABLE(...) AS X syntax
    - "validation error" → SQL violated safety rules, fix it
    - "service not available" → IBM i version may be too old

    ## Safety Rules (ENFORCED)
    - ONLY SELECT/WITH queries
    - NEVER INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, CALL
    - NEVER semicolons or SQL comments
    - ONLY schemas: QSYS2, SYSTOOLS, SYSIBM, QSYS, INFORMATION_SCHEMA

    ## Output Format
    1. **Summary**: Brief answer with appropriate emoji (📊 💾 ⚠️ ✅ 🔧 📈 ⚡ 🎯 etc.)
    2. **Evidence**: Key data points
    3. **SQL Used**: Show the query
    4. **Interpretation**: What the data means
    5. **Next Actions**: Suggested follow-ups

    ## Communication Style
    - Use relevant emojis to make responses engaging and easier to scan
    - Structure with clear headers and bullet points
    - Be concise but informative
    - Highlight important metrics and warnings with appropriate icons
""")


def build_agent() -> Agent:
    """Build the dynamic Text-to-SQL agent with 5 core tools."""
    model_id = os.getenv("OPENROUTER_MODEL_ID", "google/gemini-3-flash-preview")

    return Agent(
        name="IBM i Dynamic SQL Agent",
        model=OpenRouter(id=model_id),
        tools=[
            discover_services,
            get_table_schema,
            execute_sql,
            get_sample_data,
            list_library_objects,  # NEW: Fast library browsing
            read_source_member,     # NEW: Smart source code reading
        ],
        instructions=AGENT_INSTRUCTIONS,
        markdown=True,
    )


# =============================================================================
# MAIN LOOP
# =============================================================================

def main() -> None:
    """Main interactive loop."""
    print("=" * 60)
    print("IBM i Dynamic SQL Agent")
    print("=" * 60)
    print("This agent discovers services and generates SQL dynamically.")
    print("Ask any question about your IBM i system.")
    print("Type 'exit' or 'quit' to end the session.")
    print("=" * 60)
    print()

    # Validate credentials at startup
    try:
        creds = get_ibmi_credentials()
        print(f"[INFO] Connecting to {creds['host']}:{creds['port']} as {creds['user']}")
    except Exception as e:
        print(f"[ERROR] Configuration error: {e}")
        print("Please check your .env file or environment variables.")
        return

    # Build agent
    agent = build_agent()
    model_id = os.getenv("OPENROUTER_MODEL_ID", "google/gemini-3-flash-preview")
    print(f"[INFO] Using model: {model_id}")
    print()

    # Example prompts
    print("Example questions:")
    print("  - What is the current system status?")
    print("  - Show me jobs using the most CPU")
    print("  - List users with special authorities")
    print("  - What PTFs are installed?")
    print()

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
            # Stream events with all event types enabled
            stream = agent.run(user_input, stream=True, stream_events=True)
            for chunk in stream:
                handle_agent_event(chunk)
        except KeyboardInterrupt:
            print("\n[CANCELLED] Query cancelled by user")
        except Exception as e:
            print(f"\n[ERROR] {type(e).__name__}: {e}")

        print()  # Blank line between interactions


if __name__ == "__main__":
    main()
