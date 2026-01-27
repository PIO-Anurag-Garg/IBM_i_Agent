# IBM i Performance Agent - AI Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER INTERACTION                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ Natural Language Query
                                       │ "What jobs are using high CPU?"
                                       │ "Show me top SQL queries"
                                       │ "Check PTF status"
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CLAUDE AI AGENT (Agno)                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Agent Instructions & System Prompt                                 │    │
│  │  - "You are an expert IBM i Super Assistant"                        │    │
│  │  - "Use ONLY the provided tools"                                    │    │
│  │  - "Never ask users to run SQL manually"                            │    │
│  │  - "Provide actionable recommendations"                             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Intent Understanding & Tool Selection                              │    │
│  │  Claude analyzes query → Selects appropriate tool(s)                │    │
│  │  → Determines parameters → Plans execution sequence                 │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ Tool Invocation
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TOOL LAYER (30+ Tools)                               │
│                                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │  OBSERVABILITY   │  │  SQL PERFORMANCE │  │    SECURITY      │          │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────────┤          │
│  │ • System Status  │  │ • Plan Cache     │  │ • User Profiles  │          │
│  │ • Active Jobs    │  │ • Index Advisor  │  │ • Privileges     │          │
│  │ • Disk/ASP Info  │  │ • Lock Analysis  │  │ • Auth Lists     │          │
│  │ • Message Queue  │  │ • SQL Stats      │  │ • Special Auth   │          │
│  │ • Network Stats  │  │ • Long Queries   │  │ • Object Auth    │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │  ADMINISTRATIVE  │  │   INTEGRATION    │  │    METADATA      │          │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────────┤          │
│  │ • PTF Status     │  │ • HTTP GET       │  │ • List Schemas   │          │
│  │ • SW Inventory   │  │ • HTTP POST      │  │ • List Tables    │          │
│  │ • Journaling     │  │                  │  │ • List Routines  │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
│                                                                               │
│  ┌──────────────────┐  ┌──────────────────────────────────────┐            │
│  │ SERVICE DISCOVER │  │      CUSTOM SQL EXECUTOR              │            │
│  ├──────────────────┤  │  (with comprehensive safety checks)   │            │
│  │ • Check Service  │  └──────────────────────────────────────┘            │
│  │ • List Services  │                                                        │
│  └──────────────────┘                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ SQL Query + Parameters
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SAFETY & VALIDATION LAYER                           │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Input Validation                                                   │    │
│  │  • _safe_ident() - Validate identifiers (alphanumeric + _$#@)      │    │
│  │  • _safe_schema() - Whitelist check (QSYS2, SYSTOOLS, etc.)        │    │
│  │  • _safe_csv_idents() - Validate comma-separated lists             │    │
│  │  • _safe_limit() - Sanitize numeric limits (max 10000)             │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  SQL Guardrails                                                     │    │
│  │  • _looks_like_safe_select() - Regex pattern matching              │    │
│  │  • Forbidden: INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, etc.    │    │
│  │  • No semicolons (prevent multi-statement SQL)                     │    │
│  │  • No -- or /* */ (prevent comment-based attacks)                  │    │
│  │  • Must start with SELECT/WITH/VALUES                              │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  IBM i 7.3 Compatibility Checks                                    │    │
│  │  • service_exists() - Check service availability via cache         │    │
│  │  • _rewrite_fetch_first_param() - Rewrite parameterized queries    │    │
│  │  • Graceful fallbacks for unavailable services                     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ Validated SQL + Safe Parameters
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MAPEPIRE CONNECTION LAYER                             │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Connection Pool Manager                                            │    │
│  │  • HTTPS Transport (Port 8076 default)                              │    │
│  │  • TLS/SSL Support (ignore_unauthorized option)                     │    │
│  │  • Credential Management (from .env)                                │    │
│  │  • Connection Pooling & Reuse                                       │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Query Execution                                                    │    │
│  │  • Parameterized Query Binding (SQL injection prevention)          │    │
│  │  • Result Set Handling (JSON format)                               │    │
│  │  • Error Handling & Retry Logic                                    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ HTTPS/TLS Request
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            IBM i SYSTEM                                      │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Mapepire Server (Running on IBM i)                                │    │
│  │  • Receives HTTPS requests                                          │    │
│  │  • Authenticates user credentials                                   │    │
│  │  • Executes SQL via Db2 for i engine                               │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  QSYS2 Services (IBM i System Catalog)                             │    │
│  │                                                                      │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐ │    │
│  │  │ SYSTEM_STATUS    │  │ ACTIVE_JOB_INFO  │  │ ASP_INFO        │ │    │
│  │  │ SYSTEM_VALUE     │  │ JOB_INFO         │  │ SYSTOOLS.*      │ │    │
│  │  │ SYSTEM_ACTIVITY  │  │ MEMORY_POOL_INFO │  │ SERVICES_INFO   │ │    │
│  │  └──────────────────┘  └──────────────────┘  └─────────────────┘ │    │
│  │                                                                      │    │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────────┐ │    │
│  │  │ PLAN_CACHE_*     │  │ USER_INFO        │  │ SYSPROCS        │ │    │
│  │  │ INDEX_ADVISOR    │  │ OBJECT_PRIVILEGES│  │ SYSCOLUMNS      │ │    │
│  │  │ LOCK_WAIT        │  │ GROUP_PROFILE_*  │  │ SYSROUTINES     │ │    │
│  │  └──────────────────┘  └──────────────────┘  └─────────────────┘ │    │
│  │                                                                      │    │
│  │  + 100+ more views/table functions for system introspection        │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Db2 for i SQL Engine                                              │    │
│  │  • Query optimization                                               │    │
│  │  • Result set generation                                            │    │
│  │  • JSON formatting                                                  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ JSON Result Set
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      RESPONSE PROCESSING & ANALYSIS                          │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Result Formatting                                                  │    │
│  │  • JSON to Markdown tables                                          │    │
│  │  • Column alignment and truncation                                  │    │
│  │  • Metadata inclusion (row count, execution info)                   │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Claude AI Analysis                                                 │    │
│  │  • Pattern recognition in results                                   │    │
│  │  • Anomaly detection (high CPU, locks, etc.)                        │    │
│  │  • Correlation with domain knowledge                                │    │
│  │  • Recommendation generation                                        │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                       │                                      │
│                                       ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  Response Generation                                                │    │
│  │  • Natural language summary                                         │    │
│  │  • Actionable insights and next steps                               │    │
│  │  • Follow-up question suggestions                                   │    │
│  │  • Context-aware explanations                                       │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ Natural Language Response
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER RECEIVES                                   │
│                                                                               │
│  "I found 3 jobs using high CPU (>80%):                                     │
│                                                                               │
│  | Job Name    | User    | CPU % | Status   |                               │
│  |-------------|---------|-------|----------|                               │
│  | QZDASOINIT  | QUSER   | 92.3  | ACTIVE   |                               │
│  | QSQSRVR     | QSECOFR | 85.1  | ACTIVE   |                               │
│  | MYJOB       | APPUSER | 81.7  | ACTIVE   |                               │
│                                                                               │
│  Recommendations:                                                            │
│  1. QZDASOINIT (92.3% CPU) - Consider checking for long-running SQL         │
│  2. Review plan cache for inefficient queries                               │
│  3. Check if indexes are being utilized                                     │
│                                                                               │
│  Would you like me to:                                                       │
│  • Analyze the plan cache for these jobs?                                   │
│  • Check for lock waits?                                                    │
│  • Review index advisor recommendations?"                                   │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
                            DATA FLOW SEQUENCE
═══════════════════════════════════════════════════════════════════════════════

1. USER INPUT
   └─> Natural language question

2. CLAUDE AI (Intent Analysis)
   └─> Understands intent
   └─> Selects tool(s): get_active_jobs(cpu_threshold=80)
   └─> Determines parameters

3. TOOL EXECUTION
   └─> Python function called: @tool def get_active_jobs(...)
   └─> Constructs SQL template with parameters

4. SAFETY VALIDATION
   └─> _safe_ident() validates identifiers
   └─> _safe_limit() caps row limits
   └─> _looks_like_safe_select() checks SQL pattern
   └─> service_exists() verifies QSYS2.ACTIVE_JOB_INFO available

5. MAPEPIRE QUERY
   └─> pool.execute(sql, parameters)
   └─> HTTPS POST to IBM i Mapepire server

6. IBM i EXECUTION
   └─> Authenticate user
   └─> Execute: SELECT * FROM QSYS2.ACTIVE_JOB_INFO WHERE CPU_PCT > ?
   └─> Bind parameter: [80]
   └─> Return JSON result set

7. RESULT FORMATTING
   └─> Convert JSON to markdown table
   └─> Add metadata (row count, timestamp)

8. CLAUDE AI (Analysis)
   └─> Receives formatted results
   └─> Analyzes patterns and anomalies
   └─> Generates insights and recommendations
   └─> Suggests follow-up actions

9. USER OUTPUT
   └─> Natural language response with:
       • Summary of findings
       • Data visualization (tables)
       • Actionable recommendations
       • Follow-up suggestions


═══════════════════════════════════════════════════════════════════════════════
                         KEY ARCHITECTURAL PATTERNS
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│  PATTERN 1: TOOL-CALLING AGENT                                              │
│                                                                               │
│  Claude AI makes autonomous decisions about:                                │
│  • Which tools to invoke                                                    │
│  • What parameters to pass                                                  │
│  • How to chain multiple tools together                                     │
│  • How to interpret and present results                                     │
│                                                                               │
│  Benefits:                                                                   │
│  ✓ No rigid query parsing rules                                            │
│  ✓ Handles ambiguous/conversational queries                                │
│  ✓ Multi-step reasoning and planning                                       │
│  ✓ Context-aware follow-ups                                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  PATTERN 2: DEFENSE IN DEPTH (Security Layers)                              │
│                                                                               │
│  Layer 1: Agent Instructions                                                │
│          → "Use ONLY provided tools, don't make assumptions"                │
│                                                                               │
│  Layer 2: Input Validation                                                  │
│          → Regex patterns, whitelists, type checking                        │
│                                                                               │
│  Layer 3: SQL Guardrails                                                    │
│          → Forbidden operation detection, pattern matching                  │
│                                                                               │
│  Layer 4: Parameterized Queries                                             │
│          → SQL injection prevention via proper binding                      │
│                                                                               │
│  Layer 5: Schema Whitelist                                                  │
│          → Only QSYS2, SYSTOOLS, etc. allowed                               │
│                                                                               │
│  Layer 6: IBM i User Permissions                                            │
│          → Final enforcement at database level                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  PATTERN 3: SERVICE DISCOVERY                                               │
│                                                                               │
│  Problem: IBM i 7.3 vs 7.4+ have different service availability            │
│                                                                               │
│  Solution:                                                                   │
│  1. Check QSYS2.SERVICES_INFO at runtime                                    │
│  2. Cache results to avoid repeated queries                                 │
│  3. Provide graceful fallbacks with helpful messages                        │
│  4. Rewrite queries for compatibility (e.g., FETCH FIRST)                   │
│                                                                               │
│  Example:                                                                    │
│  if not service_exists("QSYS2", "PLAN_CACHE_SUMMARY"):                     │
│      return "Service not available. Upgrade to 7.4+ or use PLAN_CACHE"     │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  PATTERN 4: TEMPLATE-BASED SQL GENERATION                                   │
│                                                                               │
│  SQL Templates Library (~40 pre-defined queries)                            │
│  ├─ Parameterized with ? placeholders                                       │
│  ├─ Documented with comments                                                │
│  ├─ Version-specific handling                                               │
│  └─ Optimized for performance                                               │
│                                                                               │
│  Benefits:                                                                   │
│  ✓ Prevents SQL injection                                                   │
│  ✓ Ensures query quality and optimization                                  │
│  ✓ Easier testing and maintenance                                          │
│  ✓ Consistent patterns across tools                                        │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
                         EXAMPLE: MULTI-STEP REASONING
═══════════════════════════════════════════════════════════════════════════════

User Query: "Why is my system slow?"

┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: Claude's Internal Reasoning                                         │
│ "System slowness could be caused by:                                        │
│  - High CPU utilization                                                     │
│  - Memory pressure                                                          │
│  - Disk I/O bottlenecks                                                     │
│  - Long-running jobs                                                        │
│  - Lock contention                                                          │
│  Let me check all of these systematically..."                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 2: Tool Selection & Execution (Sequential)                             │
│                                                                               │
│ 1. get_system_status()                                                      │
│    → Overall CPU%, memory%, disk%                                           │
│                                                                               │
│ 2. get_active_jobs(cpu_threshold=50)                                        │
│    → Jobs consuming >50% CPU                                                │
│                                                                               │
│ 3. get_plan_cache_top_queries(limit=10)                                     │
│    → Most expensive SQL queries                                             │
│                                                                               │
│ 4. check_lock_waits()                                                       │
│    → Jobs waiting on locks                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 3: Analysis & Synthesis                                                │
│                                                                               │
│ Claude correlates findings:                                                 │
│ • CPU at 87% (high)                                                         │
│ • Job QZDASOINIT using 65% CPU                                              │
│ • Top query doing table scan on 10M row table                               │
│ • No lock waits detected                                                    │
│                                                                               │
│ Root cause identified: Missing index causing full table scan                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 4: Follow-up Tool Execution                                            │
│                                                                               │
│ 5. get_index_advisor(schema="MYLIB", table="BIGTABLE")                      │
│    → Recommended indexes for the problematic query                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 5: Actionable Response                                                 │
│                                                                               │
│ "I've identified the root cause of slowness:                                │
│                                                                               │
│ PROBLEM:                                                                     │
│ • System CPU at 87% (high)                                                  │
│ • Job QZDASOINIT consuming 65% CPU                                          │
│ • Executing query with full table scan on MYLIB.BIGTABLE (10M rows)        │
│                                                                               │
│ RECOMMENDED SOLUTION:                                                        │
│ Create index on MYLIB.BIGTABLE(CUST_ID, ORDER_DATE)                         │
│                                                                               │
│ ESTIMATED IMPACT:                                                            │
│ • Query time: 45s → <1s                                                     │
│ • CPU usage reduction: ~60%                                                 │
│                                                                               │
│ NEXT STEPS:                                                                  │
│ 1. Review the full query plan                                               │
│ 2. Create the recommended index                                             │
│ 3. Monitor performance improvement                                          │
│                                                                               │
│ Would you like me to show you the CREATE INDEX statement?"                  │
└─────────────────────────────────────────────────────────────────────────────┘
```
