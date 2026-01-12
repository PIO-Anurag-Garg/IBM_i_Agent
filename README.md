# IBM i Performance Agent 🤖

An AI-powered assistant for IBM i system administrators and developers. This intelligent agent uses Claude (Anthropic's AI model) to help you monitor, analyze, and troubleshoot your IBM i systems through natural language conversations.

## 🎯 What Does This Do?

Instead of manually writing SQL queries or navigating through IBM i system tables, simply ask questions in plain English like:

- "What are the top CPU-consuming jobs right now?"
- "Show me any jobs stuck in MSGW status"
- "Are there any PTFs requiring an IPL?"
- "Which disk units are running out of space?"
- "Show me SQL statements with the highest elapsed time"
- "List all privileged user profiles on the system"
- "Generate a disaster recovery runbook"

The AI agent will automatically:
1. Understand your question
2. Query the appropriate IBM i Services (QSYS2 views/table functions)
3. Analyze the results
4. Provide clear recommendations and next steps

## ✨ Key Features

### System Performance & Monitoring
- Real-time CPU, memory, and disk usage analysis
- Active job monitoring with detailed metrics
- Identify jobs in MSGW (message wait) state
- ASP (Auxiliary Storage Pool) information and disk hotspots
- Network connection statistics

### SQL Performance Tuning
- Plan cache analysis (top queries by elapsed time)
- SQL statement error and warning detection
- Index recommendations from IBM's INDEX_ADVICE
- Table and index statistics
- Lock wait analysis

### Security Auditing
- User profile enumeration and privileged accounts
- Object authority analysis (*PUBLIC with *ALL authority)
- Authorization list inspection
- Security-focused reporting

### Database & Catalog Exploration
- List tables, views, and routines in any schema
- Describe table structures (columns, data types, etc.)
- Search IBM i Services by name or category
- Journal and journal receiver information

### System Administration
- PTF (Program Temporary Fix) status and IPL requirements
- Software product and license information
- Message queue inspection (QSYSOPR)
- Output queue hotspots
- IFS (Integrated File System) largest objects
- Library sizing analysis

### Advanced Features
- HTTP integration (GET/POST) through IBM i Services
- Runbook and checklist generation
- Custom SQL query execution (read-only with safety guardrails)
- Optional performance metrics logging

## 🆕 What's New in IBM i 7.6 Edition

### IBM i 7.6 Native Services (10 new tools)
- **IFS Authority Analysis**: Track who can access IFS objects (`ifs-authority-collection`)
- **Name Validation**: Verify system and SQL object names (`verify-name`)
- **SQLSTATE Lookup**: Decode error codes instantly (`lookup-sqlstate`)
- **Enhanced Plan Cache**: Filter by QRO_HASH for 64-bit query optimization hash (`dump-plan-cache-qro`)
- **MFA Settings**: Inspect multi-factor authentication status for user profiles (`user-mfa-settings`)
- **Certificate Usage**: Track digital certificate deployment across applications (`certificate-usage-info`)
- **Subsystem Routing**: Detailed routing entry analysis (`subsystem-routing-info`)

### Business Data Queries (User Schema Access)
Query your application tables directly with natural language:

**Examples:**
- "Show top 10 customers by revenue"
- "List orders from yesterday with status PENDING"
- "Count rows in PRODDATA.INVENTORY"
- "Top 3 orders from yesterday by order total"

**Configuration:** Set `ALLOWED_USER_SCHEMAS=MYLIB,PRODDATA` in `.env` to enable access to your business data schemas.

**Safety:** All user schema queries are logged for audit purposes and maintain read-only restrictions.

### Program Source Code Reading
Analyze program source without leaving the AI chat:

**Capabilities:**
- Find where source code lives for any program (`get-program-source-info`)
- Read actual source code (RPG, COBOL, CL, etc.) (`read-source-member`)
- Analyze program dependencies and call chains (`analyze-program-dependencies`)

**Use Cases:**
- "Show me the source code for program MYLIB/CALCPRICE"
- "What does PAYROLL/PAYRUN call?"
- "Get source location for QGPL/MYPGM"

**Note:** Source code must still exist in source physical files. Compiled programs without source are not readable.

## 🔒 Safety First

This agent is **read-only by default**. It includes multiple safety mechanisms:

- ✅ Only SELECT/WITH queries are allowed
- ✅ Multi-statement SQL is blocked (no semicolons)
- ✅ Forbidden operations (INSERT, UPDATE, DELETE, DROP, etc.) are rejected
- ✅ Only trusted schemas (QSYS2, SYSTOOLS, SYSIBM, etc.) are accessible
- ✅ SQL injection protection through parameterized queries
- ✅ Input validation for all identifiers

## 📋 Prerequisites

Before you begin, ensure you have the following:

### 1. IBM i System Requirements
- IBM i system (version 7.3 or higher recommended)
- Mapepire server installed and running on IBM i
  - Default port: 8076
  - [Mapepire Installation Guide](https://github.com/Mapepire-IBMi/mapepire-server)
- User credentials with appropriate authorities:
  - *READ access to QSYS2 views and table functions
  - Authority to execute SQL queries

### 2. Development Environment
- **Python 3.8 or higher** installed on your workstation
- Git (for cloning the repository)
- A text editor or IDE (VS Code, PyCharm, etc.)

### 3. API Keys
- **Anthropic API Key** - Get one from [Anthropic Console](https://console.anthropic.com/)
  - You'll need to create an account and add payment information
  - Claude models are pay-per-use (very affordable for this use case)

### 4. Network Access
- Your workstation must be able to connect to the IBM i system
- Port 8076 (or your configured Mapepire port) must be accessible
- Consider VPN if accessing remotely

## 🚀 Installation Guide

### Step 1: Fork This Repository

1. **Go to the GitHub repository**: [https://github.com/PIO-Anurag-Garg/IBM_i_Agent](https://github.com/PIO-Anurag-Garg/IBM_i_Agent)

2. **Click the "Fork" button** in the top-right corner of the page
   - This creates a copy of the repository under your GitHub account

3. **Clone your forked repository** to your local machine:
   ```bash
   git clone https://github.com/YOUR-USERNAME/IBM_i_Agent.git
   cd IBM_i_Agent
   ```
   
   Replace `YOUR-USERNAME` with your actual GitHub username.

### Step 2: Set Up Python Virtual Environment

A virtual environment keeps this project's dependencies isolated from your system Python.

**On Windows (PowerShell):**
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# If you get an execution policy error, run this first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**On Windows (Command Prompt):**
```cmd
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate.bat
```

**On macOS/Linux:**
```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate
```

You should see `(.venv)` at the beginning of your command prompt when activated.

### Step 3: Install Required Python Packages

With the virtual environment activated, install all dependencies:

```bash
pip install --upgrade pip
pip install python-dotenv mapepire-python agno anthropic
```

**Package explanations:**
- `python-dotenv`: Loads environment variables from .env file
- `mapepire-python`: Python client for IBM i database access
- `agno`: AI agent framework for tool calling and orchestration
- `anthropic`: Official Anthropic API client for Claude models

### Step 4: Configure Environment Variables

1. **Copy the example environment file:**
   ```bash
   # Windows PowerShell/Command Prompt
   copy .env.example .env
   
   # macOS/Linux
   cp .env.example .env
   ```

2. **Edit the `.env` file** with your favorite text editor and fill in your details:

   ```dotenv
   # IBM i / Mapepire Connection
   IBMI_HOST=your-ibmi-hostname.example.com
   IBMI_PORT=8076
   IBMI_USER=your_username
   IBMI_PASSWORD=your_password
   
   # Set to true if using self-signed certificates
   IBMI_IGNORE_UNAUTHORIZED=true
   
   # Anthropic API Configuration
   ANTHROPIC_API_KEY=sk-ant-api03-your-actual-api-key-here
   
   # Claude Model Selection
   # Haiku is faster and cheaper, Sonnet is more capable
   CLAUDE_MODEL_ID=claude-haiku-4-5-20251001
   # CLAUDE_MODEL_ID=claude-sonnet-4-5-20250929
   
   # Optional: Report output directory
   # REPORT_BASE_DIR=./reports
   
   # Optional: Advanced tuning
   # ROUTER_CONFIDENCE_THRESHOLD=0.65
   # ROUTER_AUDIT_LOG=router_audit.jsonl
   # ENABLE_DB_AUDIT_LOG=0
   # ENABLE_ACTION_TOOLS=0
   ```

   **Important Notes:**
   - Replace `IBMI_HOST` with your actual IBM i hostname or IP address
   - Replace `IBMI_USER` and `IBMI_PASSWORD` with your IBM i credentials
   - Replace `ANTHROPIC_API_KEY` with your actual API key from Anthropic
   - The `.env` file is ignored by Git and will NOT be committed (it's in .gitignore)

### Step 5: Verify Installation

Test that everything is set up correctly:

```bash
python ibmi_agent.py
```

If successful, you should see:

```
✅ IBM i Super Agent is ready (single agent, all tools).
Try questions like:
 - 'What are the top CPU jobs right now?'
 - 'Any jobs stuck in MSGW? Show details.'
 - 'Show ASP info and disk hotspots.'
 ...

Type a question (or 'exit' to quit).

You> 
```

## 💡 Usage Examples

Once the agent is running, try these example questions:

### System Health Check
```
You> What's the overall system status?
You> Show me CPU utilization and memory usage
You> Are there any disk space issues?
```

### Job Monitoring
```
You> What are the top 5 CPU consuming jobs?
You> Show me all jobs in MSGW status
You> List any recently ended jobs with errors
```

### SQL Performance
```
You> What are the slowest SQL queries in the plan cache?
You> Show me queries with errors or warnings
You> What indexes does IBM recommend I create?
```

### Security Audit
```
You> List all user profiles with *ALLOBJ authority
You> Show objects where *PUBLIC has *ALL authority
You> What special authorities do privileged users have?
```

### Database Exploration
```
You> List all tables in schema MYLIB
You> Describe the structure of table MYLIB.CUSTOMERS
You> What stored procedures exist in QSYS2?
```

### Operational Tasks
```
You> Are there any PTFs waiting for an IPL?
You> Generate a disaster recovery runbook
You> Show me the largest objects in library PRODDATA
You> What are the top 10 largest libraries on the system?
```

### Troubleshooting
```
You> Why is my system slow?
You> Check for lock waits
You> Show me recent QSYSOPR messages
You> What's consuming the most disk I/O?
```

## 🔧 Configuration Options

### Model Selection

Choose between different Claude models based on your needs:

- **claude-haiku-4-5-20251001** (Default)
  - Fastest responses
  - Most cost-effective
  - Great for routine monitoring

- **claude-sonnet-4-5-20250929**
  - More sophisticated analysis
  - Better at complex reasoning
  - Slightly higher cost

Edit in `.env`:
```dotenv
CLAUDE_MODEL_ID=claude-sonnet-4-5-20250929
```

### Optional Features

Enable additional features in `.env`:

```dotenv
# Save performance metrics to disk
ENABLE_DB_AUDIT_LOG=1

# Enable write operations (USE WITH CAUTION)
ENABLE_ACTION_TOOLS=1

# Custom report output directory
REPORT_BASE_DIR=/path/to/reports

# Router confidence threshold (advanced)
ROUTER_CONFIDENCE_THRESHOLD=0.65

# Audit log for router decisions
ROUTER_AUDIT_LOG=router_audit.jsonl
```

## 📁 Project Structure

```
IBM_i_Agent/
├── ibmi_agent.py          # Main agent application
├── .env.example           # Example environment configuration
├── .env                   # Your actual configuration (not in Git)
├── .gitignore            # Git ignore file
├── README.md             # This file
└── .venv/                # Virtual environment (not in Git)
```

## 🐛 Troubleshooting

### Connection Errors

**Problem:** `Connection refused` or `Unable to connect to IBM i`

**Solutions:**
- Verify Mapepire server is running on IBM i
- Check that port 8076 is open and accessible
- Confirm hostname/IP address is correct in `.env`
- Test network connectivity: `ping your-ibmi-hostname`

### Authentication Errors

**Problem:** `Authentication failed` or `Invalid credentials`

**Solutions:**
- Verify username and password in `.env` file
- Ensure user has appropriate IBM i authorities
- Check if user profile is enabled (not disabled)
- Test credentials with another tool (ODBC, SSH, etc.)

### Anthropic API Errors

**Problem:** `Invalid API key` or `Rate limit exceeded`

**Solutions:**
- Verify API key is correct in `.env` file
- Check your Anthropic account has available credits
- Ensure API key hasn't expired or been revoked
- Visit [Anthropic Console](https://console.anthropic.com/) to check status

### Missing Python Packages

**Problem:** `ModuleNotFoundError: No module named 'X'`

**Solutions:**
- Ensure virtual environment is activated (you should see `(.venv)`)
- Reinstall packages: `pip install -r requirements.txt`
- Or install individually: `pip install python-dotenv mapepire-python agno anthropic`

### Permission Errors on IBM i

**Problem:** `SQL Error: Authority not allowed` or `Not authorized to service`

**Solutions:**
- Grant user *READ authority to QSYS2 library
- Use WRKOBJ or EDTOBJAUT to check specific object authorities
- Contact your IBM i system administrator for proper authorities

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please ensure your code:
- Follows Python best practices (PEP 8)
- Includes appropriate error handling
- Maintains the read-only safety model (unless explicitly adding admin features)
- Is well-documented

## 📄 License

This project is provided as-is for educational and operational purposes. Please review your organization's policies regarding AI tool usage before deploying in production environments.

## 🙏 Acknowledgments

- **IBM i Services** (QSYS2) - The foundation for system introspection
- **Mapepire** - Python connectivity to IBM i
- **Anthropic** - Claude AI models powering the intelligence
- **Agno Framework** - Agent orchestration and tool management

## 📞 Support

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/PIO-Anurag-Garg/IBM_i_Agent/issues)
- **Discussions**: Ask questions in [GitHub Discussions](https://github.com/PIO-Anurag-Garg/IBM_i_Agent/discussions)

## 🔐 Security Note

**Never commit your `.env` file or share your credentials!**

- The `.env` file contains sensitive information (passwords, API keys)
- This file is automatically excluded from Git via `.gitignore`
- Use `.env.example` as a template for others to follow
- Rotate credentials regularly and use strong passwords

## 🚦 Getting Started Checklist

- [ ] Python 3.8+ installed
- [ ] Git installed
- [ ] Repository forked and cloned
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install ...`)
- [ ] Mapepire server running on IBM i
- [ ] IBM i credentials obtained
- [ ] Anthropic API key obtained
- [ ] `.env` file created and configured
- [ ] Successfully ran `python ibmi_agent.py`
- [ ] Asked first question and got response!

---

**Happy monitoring! 🚀 May your IBM i systems run smoothly and your queries return quickly!**