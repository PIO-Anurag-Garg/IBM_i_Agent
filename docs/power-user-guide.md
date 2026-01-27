# IBM i Performance Agent - Power User Query Guide

This document lists **all possible queries** you can ask the IBM i Performance Agent. The agent has **72 tools** that cover system monitoring, security, performance tuning, and more.

---

## Table of Contents

1. [System Performance & Monitoring](#1-system-performance--monitoring)
2. [Job Management & Analysis](#2-job-management--analysis)
3. [CPU & Memory Analysis](#3-cpu--memory-analysis)
4. [Disk & Storage](#4-disk--storage)
5. [Network & Connections](#5-network--connections)
6. [Security & User Profiles](#6-security--user-profiles)
7. [SQL Performance Tuning](#7-sql-performance-tuning)
8. [PTF & Software Management](#8-ptf--software-management)
9. [Database & Schema Exploration](#9-database--schema-exploration)
10. [IFS (Integrated File System)](#10-ifs-integrated-file-system)
11. [Journals & HA/DR](#11-journals--hadr)
12. [System Configuration](#12-system-configuration)
13. [HTTP Integration](#13-http-integration)
14. [Program & Source Code Analysis](#14-program--source-code-analysis)
15. [Business Data Queries](#15-business-data-queries)
16. [Templates & Runbooks](#16-templates--runbooks)
17. [IBM i 7.5+ Features](#17-ibm-i-75-features)
18. [IBM i 7.6 Features](#18-ibm-i-76-features)
19. [Troubleshooting Scenarios](#19-troubleshooting-scenarios)
20. [Daily Operations](#20-daily-operations)

---

## 1. System Performance & Monitoring

### Basic System Status
```
What is the current system status?
Show me IBM i system health
Give me an overview of system performance
How is my IBM i doing right now?
What's the CPU usage on the system?
Show system statistics
Get system performance metrics
What is the current state of my AS/400?
Display system activity
How busy is my IBM i system?
```

### System Activity
```
Show current system activity
What's happening on the system right now?
Display real-time system metrics
Show me system activity information
What is the current workload?
```

### ASP (Auxiliary Storage Pool) Information
```
Show ASP information
What's the disk space usage?
How much storage is available?
Display ASP status
Show me auxiliary storage pool details
What's the ASP capacity?
Are any ASPs running low on space?
Show disk pool information
```

---

## 2. Job Management & Analysis

### Active Jobs
```
Show all active jobs
List running jobs on the system
What jobs are currently running?
Display active job information
How many jobs are active?
Show me detailed job information
List jobs with their CPU usage
What's running on the system?
```

### Jobs in Message Wait (MSGW)
```
Are there any jobs stuck in MSGW?
Show jobs waiting for messages
List jobs in message wait status
Find jobs that need attention
Which jobs are in MSGW?
Show me stuck jobs
Any jobs waiting for operator reply?
Display MSGW jobs with details
```

### Ended Jobs
```
Show recently ended jobs
What jobs ended in the last hour?
List completed jobs
Show job history
Which jobs finished recently?
Display ended job information
```

### Job Queue Analysis
```
Show job queue entries
What's waiting in the job queues?
List queued jobs
How many jobs are waiting to run?
Display job queue status
Which jobs are pending?
```

### Job Log Analysis
```
Show job log for job 123456/MYUSER/MYJOB
Read job log messages for QPADEV0001
What errors are in the job log?
Display job log with severity 30 or higher
Show recent job log entries
Get job log for specific job
```

### Spooled Files
```
Show spooled files on the system
List print output waiting
What's in the output queues?
Display spool file information
Which jobs have spooled output?
Show largest spooled files
```

---

## 3. CPU & Memory Analysis

### Top CPU Consumers
```
What are the top CPU consuming jobs?
Show top 10 jobs by CPU usage
Which jobs are using the most CPU?
List jobs with highest CPU time
Find CPU hogs on the system
Show top 20 CPU jobs
Display CPU-intensive jobs
Who is using all the CPU?
```

### CPU by Subsystem
```
Show top CPU jobs in QBATCH
List CPU usage for subsystem QINTER
Which interactive jobs use most CPU?
Show batch job CPU consumption
Filter CPU jobs by subsystem QSYSWRK
```

### CPU by User
```
Show CPU usage for user MYUSER
Which users are consuming the most CPU?
List top CPU jobs for specific users
Filter by user QSECOFR
Show CPU time for user profile DEVELOPER
```

### Memory Pools
```
Show memory pool information
How is memory allocated?
Display subsystem pool allocations
What's the memory distribution?
Show pool faulting rates
```

---

## 4. Disk & Storage

### Disk Hotspots
```
Show disk hotspots
Which disks are almost full?
Display disks with highest utilization
Find disks running out of space
Show disk usage percentages
Which disk units need attention?
List disks over 80% full
Show disk capacity information
```

### Disk Configuration
```
Show disk block size information
Display disk configuration details
What's the disk protection level?
Show RAID information
Display disk unit details
```

### Library Sizes
```
Show library sizes
Which libraries are largest?
List libraries by size
How big is library MYLIB?
Show top 50 largest libraries
Display library storage consumption
Exclude system libraries from size report
```

### Largest Objects
```
Show largest objects in MYLIB
Find biggest objects in library PRODDATA
List top 20 largest objects
What's taking up space in QGPL?
Show objects by size in specific library
Find all large objects across all libraries
```

### User Storage
```
Show storage by user profile
Which users consume the most disk?
List top storage consumers
Who is using the most space?
Display user storage allocation
```

### Output Queue Hotspots
```
Show output queues with most files
Which output queues are full?
Find busy output queues
List print queues by file count
Display output queue hotspots
```

---

## 5. Network & Connections

### Network Status
```
Show network connections
Display netstat information
What network connections are active?
List TCP/IP connections
Show established connections
How many connections are open?
```

### Network by Job
```
Show network connections with job names
Which jobs have network connections?
Map connections to owning jobs
Display network job information
Find what job owns this connection
```

---

## 6. Security & User Profiles

### User Profile Listing
```
List all user profiles
Show user profiles on the system
How many users are defined?
Display user information
List enabled user profiles
```

### Privileged Users
```
Show privileged user profiles
List users with special authorities
Who has *ALLOBJ authority?
Find users with *SECADM
Show accounts with failed sign-on attempts
List users with elevated privileges
Find disabled user profiles
Show users with *IOSYSCFG authority
```

### MFA Settings (IBM i 7.6)
```
Show MFA status for users
Which users have MFA enabled?
List TOTP authentication settings
Check MFA enrollment for user MYUSER
Display multi-factor authentication status
```

### Object Authorities
```
Show authorities for object MYOBJ in MYLIB
Who has access to this file?
List permissions for table ORDERS
Display object privileges
What authorities does *PUBLIC have?
```

### Public *ALL Authority (Security Risk)
```
Find objects where PUBLIC has *ALL authority
Show security risks - public access
List overly permissive objects
Find objects with excessive public authority
Security audit - public *ALL
```

### Authorization Lists
```
Show authorization lists
List all auth lists on system
Display authorization list entries
What's in auth list MYAUTL?
Show entries for authorization list in QSYS
```

### Security Configuration
```
Show system security settings
What's the security level?
Display security configuration
Show password rules
What are the audit settings?
Display QSECURITY system value
```

### Certificate Management (IBM i 7.5+)
```
Show certificate usage
Which applications use certificates?
Display digital certificate information
List SSL/TLS certificates in use
Show certificate store contents
```

---

## 7. SQL Performance Tuning

### Top SQL Statements
```
Show top SQL statements by elapsed time
Which queries are slowest?
List expensive SQL statements
Find SQL performance problems
Show top 50 queries by execution time
Display plan cache statistics
```

### SQL Errors and Warnings
```
Show SQL statements with errors
Find queries with warnings
List problematic SQL
Which statements are failing?
Display SQL error statistics
```

### Index Recommendations
```
Show index advice
What indexes should I create?
Display index recommendations
List suggested indexes
Show index advisor results
Which indexes would help performance?
```

### Table Statistics
```
Show table statistics for schema MYLIB
List largest tables in library
Display table sizes
What tables have the most rows?
Show table storage for PRODDATA schema
```

### Index Statistics
```
Show index usage for table ORDERS in MYLIB
Which indexes are being used?
Display index statistics
Are my indexes effective?
Show index scan counts
```

### Lock Analysis
```
Show current lock waits
Who is blocking whom?
Display lock contention
Find lock holders
Show waiting jobs for locks
```

### Plan Cache by QRO Hash (IBM i 7.6)
```
Dump plan cache for QRO hash 1234567890
Show execution plan for specific query hash
Get plan details for QRO 9876543210
Analyze specific SQL statement by hash
```

---

## 8. PTF & Software Management

### PTFs Requiring IPL
```
Show PTFs requiring IPL
Are there pending PTFs?
List PTFs that need a restart
What PTFs require system IPL?
When do I need to IPL for PTFs?
```

### PTF Status
```
Show PTF information
List applied PTFs
What PTFs are installed?
Display PTF status
Check for superseded PTFs
```

### PTF Supersession
```
Show superseded PTFs
Which PTFs have been replaced?
List PTF supersession chain
Find outdated PTFs
```

### Software Products
```
List installed software products
What's installed on the system?
Show licensed programs
Display software inventory
Find specific product 5770SS1
Show all IBM products
```

### License Information
```
Show license information
What licenses are installed?
Display license keys
Check license compliance
Show licensed processor features
```

---

## 9. Database & Schema Exploration

### Tables in Schema
```
List tables in schema MYLIB
Show all tables in PRODDATA
What tables exist in QGPL?
Display views in schema
List physical files in library
Find tables starting with ORD
```

### Table Description
```
Describe table ORDERS in MYLIB
Show columns for CUSTOMERS table
What fields are in INVENTORY?
Display table structure
Get column definitions for MYFILE
Show data types for table
```

### Routines (Procedures/Functions)
```
List routines in schema MYLIB
Show stored procedures
What functions exist in library?
Display SQL routines
Find procedures starting with GET
```

### IBM i Services Discovery
```
Search for SQL services about jobs
Find services for security
What IBM i services exist for performance?
Search services catalog for PTF
List available QSYS2 services
Find services related to IFS
```

---

## 10. IFS (Integrated File System)

### IFS Largest Files
```
Show largest files in /home
Find big files in IFS path /tmp
List largest objects in /QIBM
What's taking space in root?
Show top 50 largest IFS files
Find files over 100MB in /mydir
```

### IFS Object Statistics
```
Show IFS statistics for /home/myuser
Display IFS object details
List files in directory with sizes
Get IFS file information
Show file timestamps in /mypath
```

### IFS Locks
```
Who is locking file /home/myfile.txt?
Show IFS object locks
Find jobs holding IFS locks
Display lock information for path
Which job has file locked?
```

### IFS Authority Collection (IBM i 7.6)
```
Show IFS authority analysis
Who can access files in /home?
Display IFS permissions
Analyze IFS security
Show authority collection for path pattern
```

---

## 11. Journals & HA/DR

### Journal Information
```
Show journals on the system
List all journals
Display journal configuration
What journals exist?
Show journaling status
```

### Journal Receivers
```
Show journal receivers
List receivers for journal QAUDJRN
Display journal receiver sizes
How many receivers are attached?
Show journal receiver chain
```

---

## 12. System Configuration

### System Values
```
Show all system values
What is QSECURITY set to?
Display system value QCCSID
Search system values for DATE
Show password system values
List audit-related system values
```

### Library List
```
Show my library list
What's in the current library list?
Display job library list
What libraries am I using?
Show system and user libraries
```

### Hardware Information
```
Show hardware configuration
What processors does the system have?
Display hardware resources
List system hardware
Show memory configuration
What's the system serial number?
```

---

## 13. HTTP Integration

### HTTP GET
```
Call HTTP GET for URL https://api.example.com/status
Fetch data from REST API
Make HTTP request to external service
Get JSON from web service
```

### HTTP POST
```
Call HTTP POST to https://api.example.com/data with body {"key":"value"}
Send data to REST API
Post JSON payload
Submit form data via HTTP
```

### HTTP PATCH (IBM i 7.4+)
```
Call HTTP PATCH to update resource
Send PATCH request with JSON body
Update via REST API PATCH method
```

### HTTP DELETE (IBM i 7.4+)
```
Call HTTP DELETE to remove resource
Delete via REST API
Send DELETE request to URL
```

---

## 14. Program & Source Code Analysis

### Find Program Source
```
Where is the source for program MYPGM in MYLIB?
Find source file for ORDENTRY
Show source location for program
What source file contains MYPGM?
Get program source information
```

### Read Source Code
```
Show source code for member MYPGM in QRPGLESRC in MYLIB
Read RPG source member
Display CL source code
Show program source listing
Read COBOL source member
Get source for SQLRPGLE program
```

### Program Dependencies
```
What does program MYPGM reference?
Show program dependencies for ORDENTRY in MYLIB
List objects called by program
Display service program bindings
What files does this program use?
Show program reference analysis
```

---

## 15. Business Data Queries

> **Note:** Requires `ALLOWED_USER_SCHEMAS` environment variable to be configured.

### Query Application Tables
```
Show top 10 customers by revenue from PRODDATA.CUSTOMERS
List orders from yesterday in MYLIB.ORDERS
Query INVENTORY table for low stock items
Select records where STATUS = 'PENDING'
Show recent transactions from SALES table
```

### Describe Application Tables
```
Describe table CUSTOMERS in PRODDATA
Show columns in my application table
What fields are in ORDERS?
Get structure of business table
```

### Count Rows
```
How many rows in PRODDATA.ORDERS?
Count records in CUSTOMERS table
What's the row count for INVENTORY?
How big is my application table?
```

---

## 16. Templates & Runbooks

### DR Runbook
```
Generate a disaster recovery runbook
Create DR drill template
Show DR procedure checklist
Generate switchover runbook
```

### Checklists
```
Generate a release checklist
Create security audit checklist
Show performance triage checklist
Generate integration cutover checklist
Create custom checklist for deployment
```

---

## 17. IBM i 7.5+ Features

### Enhanced Job Information
```
Show active jobs with SQL text
Display jobs with QRO hash
Get detailed job information (WORK mode)
Show jobs with enhanced metrics
```

### Network Job Mapping
```
Show network connections with owning jobs
Map TCP connections to jobs
Which job owns this socket?
Display netstat with job names
```

### System Security Configuration
```
Show security info
Display security configuration details
What's the system security posture?
Show password composition rules
```

### Database Transactions
```
Show active database transactions
List uncommitted transactions
Find long-running transactions
Display transaction locks
Any deadlocks detected?
```

### Spooled File Analysis
```
Show all spooled files
List print jobs waiting
Display spool file details
Which jobs have pending output?
Show largest print files
```

---

## 18. IBM i 7.6 Features

### Name Validation
```
Verify if MYNAME is a valid system name
Check if identifier is valid SQL name
Validate object name format
Is this a legal IBM i name?
```

### SQLSTATE Lookup
```
What does SQLSTATE 42S02 mean?
Lookup error code 42601
Explain SQL error state
Decode SQLSTATE 22001
What's the meaning of 23505?
```

### Fast Active Jobs Query
```
Quick active job snapshot
Show jobs using FULL mode
Fast job status check
Get active jobs without slow columns
```

### Subsystem Routing
```
Show subsystem routing entries
Display routing configuration
What routing entries exist for QINTER?
Show server subsystem routing
```

### Memory Pools
```
Show subsystem memory pools
Display pool allocations
What memory is assigned to subsystems?
Show pool activity levels
```

---

## 19. Troubleshooting Scenarios

### Performance Problems
```
The system is slow, what's wrong?
Why is CPU so high?
Find the cause of poor performance
System seems sluggish, diagnose it
What's causing the slowdown?
Show me everything about system performance
```

### Job Issues
```
Why is my job stuck?
Job MYJOB won't complete, what's happening?
Diagnose job problems
Why is this job in MSGW?
What's blocking my batch job?
```

### Disk Space Issues
```
System is running out of disk space, help!
Which libraries are consuming space?
Find what's filling up the disk
Why is ASP1 almost full?
Clean up disk space recommendations
```

### Security Audit
```
Run a security audit
Check for security vulnerabilities
Find accounts with too many privileges
Are there any security risks?
Audit user authorities
Check public access objects
```

### Application Troubleshooting
```
Why is my SQL slow?
This query takes forever, analyze it
Find performance bottlenecks
Show plan cache for slow statements
Index recommendations for my schema
```

### Connection Problems
```
Show all network connections
Who is connected to the system?
Check for network issues
Display connection statistics
```

---

## 20. Daily Operations

### Morning Health Check
```
Give me a morning system health check
Show system status summary
Quick health overview
Daily system check
Everything look OK today?
```

### Capacity Planning
```
Show disk capacity trends
How much storage do we have left?
When will we run out of space?
Show growth trends
Capacity planning report
```

### Security Review
```
Daily security check
Any failed sign-on attempts?
Show new user profiles
Check for privilege changes
Security events today
```

### Performance Baseline
```
Capture performance baseline
Show typical system metrics
What's normal for this system?
Performance snapshot for comparison
```

### End of Day Summary
```
End of day system summary
Show jobs that completed today
Any errors or warnings today?
Daily operations report
What happened today on the system?
```

---

## Quick Reference: All 72 Tools

| # | Tool Name | Description |
|---|-----------|-------------|
| 1 | get-system-status | Overall system performance (CPU, memory, disk) |
| 2 | get-system-activity | Real-time system activity metrics |
| 3 | top-cpu-jobs | Top CPU consuming jobs |
| 4 | jobs-in-msgw | Jobs stuck in message wait |
| 5 | qsysopr-messages | QSYSOPR message queue |
| 6 | netstat-snapshot | Network connections |
| 7 | get-asp-info | ASP/disk pool information |
| 8 | disk-hotspots | Disks with high utilization |
| 9 | output-queue-hotspots | Busy output queues |
| 10 | ended-jobs | Recently completed jobs |
| 11 | job-queue-entries | Jobs waiting in queues |
| 12 | user-storage-top | Storage by user profile |
| 13 | ifs-largest-objects | Largest IFS files |
| 14 | objects-changed-recently | Recently modified objects |
| 15 | ptfs-requiring-ipl | PTFs needing IPL |
| 16 | software-products | Installed software |
| 17 | license-info | License information |
| 18 | search-sql-services | Search IBM i services catalog |
| 19 | list-user-profiles | All user profiles |
| 20 | list-privileged-profiles | Users with special authorities |
| 21 | public-all-object-authority | Objects with *PUBLIC *ALL |
| 22 | object-privileges | Object permissions |
| 23 | authorization-lists | Auth list catalog |
| 24 | authorization-list-entries | Auth list details |
| 25 | plan-cache-top | Top SQL by elapsed time |
| 26 | plan-cache-errors | SQL with errors/warnings |
| 27 | index-advice | Index recommendations |
| 28 | schema-table-stats | Table sizes in schema |
| 29 | table-index-stats | Index usage for table |
| 30 | lock-waits | Lock contention |
| 31 | journals | Journal configuration |
| 32 | journal-receivers | Journal receiver info |
| 33 | http-get-verbose | HTTP GET requests |
| 34 | http-post-verbose | HTTP POST requests |
| 35 | http-patch-verbose | HTTP PATCH (7.4+) |
| 36 | http-delete-verbose | HTTP DELETE (7.4+) |
| 37 | system-values | System value settings |
| 38 | library-list-info | Current library list |
| 39 | hardware-resource-info | Hardware configuration |
| 40 | security-info | Security configuration |
| 41 | db-transaction-info | Active transactions |
| 42 | active-jobs-detailed | Jobs with SQL/QRO info |
| 43 | joblog-info | Job log messages |
| 44 | netstat-job-info | Network with job mapping |
| 45 | spooled-file-info | Print/spool files |
| 46 | ifs-object-stats | IFS statistics |
| 47 | ifs-object-locks | IFS file locks |
| 48 | largest-objects | Biggest objects in library |
| 49 | library-sizes | Library storage |
| 50 | list-tables-in-schema | Tables in schema |
| 51 | describe-table | Table column details |
| 52 | list-routines-in-schema | Procedures/functions |
| 53 | log-performance-metrics | Save perf metrics |
| 54 | generate-runbook | DR/switchover templates |
| 55 | generate-checklist | Operations checklists |
| 56 | ifs-authority-collection | IFS security audit (7.6) |
| 57 | verify-name | Name validation (7.6) |
| 58 | lookup-sqlstate | SQLSTATE decoder (7.6) |
| 59 | dump-plan-cache-qro | Plan cache by hash (7.6) |
| 60 | certificate-usage-info | Certificate audit (7.5+) |
| 61 | user-mfa-settings | MFA status (7.6) |
| 62 | subsystem-routing-info | Routing entries (7.6) |
| 63 | active-jobs-full | Fast job query (7.6) |
| 64 | disk-block-size-info | Disk configuration |
| 65 | subsystem-pool-info | Memory pools (7.4+) |
| 66 | ptf-supersession | Superseded PTFs |
| 67 | get-program-source-info | Find program source |
| 68 | read-source-member | Read source code |
| 69 | analyze-program-dependencies | Program references |
| 70 | query-user-table | Query business data |
| 71 | describe-user-table | Describe app table |
| 72 | count-user-table-rows | Row counts |

---

## Tips for Better Queries

1. **Be specific**: "Show top 10 CPU jobs" is better than "Show jobs"
2. **Use filters**: "Show jobs in subsystem QBATCH" narrows results
3. **Ask follow-ups**: "Now show the job log for that job"
4. **Combine queries**: "Show system status and top CPU jobs"
5. **Use natural language**: The agent understands conversational requests

---

*Generated for IBM i Performance Agent v7.6 Edition (72 tools)*
