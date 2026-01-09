
import os
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
    return {
        "host": _require_env("IBMI_HOST"),
        "port": int(_require_env("IBMI_PORT", "8076")),
        "user": _require_env("IBMI_USER"),
        "password": _require_env("IBMI_PASSWORD"),
        # If you're using TLS with self-signed certs, you may need:
        # "ignoreUnauthorized": True
    }


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
            # The TechChannel article checks cur.has_results and then uses cur.fetchall()["data"].
            # We'll handle multiple shapes safely.
            if getattr(cur, "has_results", False):
                raw = cur.fetchall()
                # Common Mapepire shape is: {"metadata": ..., "data": ...}
                if isinstance(raw, dict) and "data" in raw:
                    return format_mapepire_result(raw["data"])
                return format_mapepire_result(raw)
            return "SQL executed successfully. No results returned."


# --- IBM i SQL Services used in the article ---
SYSTEM_STATUS_SQL = (
    "SELECT * FROM TABLE(QSYS2.SYSTEM_STATUS(RESET_STATISTICS=>'YES', DETAILED_INFO=>'ALL')) X"
)
SYSTEM_ACTIVITY_SQL = "SELECT * FROM TABLE(QSYS2.SYSTEM_ACTIVITY_INFO())"


# --- Tools (agent-callable functions) ---
@tool(
    name="get-system-status",
    description="Retrieve overall IBM i system performance statistics (SYSTEM_STATUS).",
)
def get_system_status() -> str:
    return run_sql_statement(SYSTEM_STATUS_SQL)


@tool(
    name="get-system-activity",
    description="Retrieve current IBM i activity metrics (SYSTEM_ACTIVITY_INFO), including CPU and jobs.",
)
def get_system_activity() -> str:
    return run_sql_statement(SYSTEM_ACTIVITY_SQL)


@tool(
    name="log-performance-metrics",
    description="Save performance metrics to SAMPLE.METRICS for monitoring trend history.",
)
def log_performance_metrics(cpu_usage: float, asp_usage: float) -> str:
    sql = """
        INSERT INTO SAMPLE.METRICS (TIMESTAMP, CPU_PCT, ASP_PCT)
        VALUES (CURRENT_TIMESTAMP, ?, ?)
    """
    return run_sql_statement(sql, parameters=[cpu_usage, asp_usage])


def build_agent() -> Agent:
    """
    Create the agent with:
    - A Claude model (Anthropic API key must be set)
    - Tools that run fixed SQL (safer than arbitrary SQL execution)
    - Instructions that enforce business-friendly explanations
    """
    model_id = os.getenv("CLAUDE_MODEL_ID", "claude-sonnet-4-5-20250929")

    return Agent(
        name="IBM i Performance Metrics Assistant",
        model=Claude(id=model_id),
        tools=[get_system_status, get_system_activity, log_performance_metrics],
        instructions=dedent(
            """
            You are an expert IBM i performance metrics assistant.

            Goals:
            - When asked about performance, call one or both tools to fetch current data.
            - Summarize key metrics in business-friendly language.
            - Highlight any concerning values (e.g., high CPU, too many jobs, high storage usage).
            - If you cannot find a metric in tool output, say so and suggest the closest available metric.

            Style:
            - Use Markdown formatting.
            - Provide a short "Summary" followed by "Details".
            """
        ).strip(),
        markdown=True,
    )


def main():
    # Fail fast if required env vars are not present
    _ = get_ibmi_credentials()
    _ = _require_env("ANTHROPIC_API_KEY")

    agent = build_agent()

    print("\n✅ IBM i Performance Agent is ready.")
    print("Type a question (or 'exit' to quit).\n")

    while True:
        user_q = input("You> ").strip()
        if user_q.lower() in {"exit", "quit"}:
            break
        if not user_q:
            continue

        # print_response streams a formatted response in console
        agent.print_response(user_q)


if __name__ == "__main__":
    main()
