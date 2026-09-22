# Security Intelligence & Detection Platform

A cybersecurity platform designed to analyze IP addresses and domains, perform security checks, identify potential risks, track changes over time, and correlate findings with external threat intelligence sources.

The main goal of this project is to build a security analysis engine rather than simply displaying information retrieved from existing platforms.

The platform performs its own DNS, HTTP/HTTPS, TLS and network analysis, with custom detection rules, risk scoring, historical analysis, threat intelligence enrichment and a web dashboard planned as subsequent development stages.



---

## 1. Project Goals

The platform allows a security analyst to submit an:

* IP address
* Domain name

The system is being developed incrementally and currently supports:

1. Target identification.
2. DNS analysis.
3. HTTP/HTTPS analysis.
4. TLS certificates and configuration.
5. Controlled network/port analysis.

The following capabilities are planned:

6. Custom security detection rules.
7. Risk scoring.
8. Historical result storage.
9. Comparison with previous scans.
10. External threat-intelligence enrichment.
11. Web dashboard.

The project is being developed incrementally, starting with the core analysis engine and progressively adding the detection engine, database, web application, containerization and CI/CD.

---

# 2. Core Concept

The platform is not intended to be a simple API aggregator.

Instead of:

```text
User
  ↓
Our Application
  ↓
External API
  ↓
Display Results
```

The main architecture will be:

```text
User
  │
  ▼
Target
(IP / Domain)
  │
  ▼
┌─────────────────────────────┐
│      Analysis Engine        │
├─────────────────────────────┤
│ DNS Analysis                │
│ HTTP Analysis               │
│ TLS Analysis                │
│ Port Analysis               │
└──────────────┬──────────────┘
               │
               ▼
      Detection Engine
               │
               ▼
        Risk Assessment
               │
       ┌───────┴────────┐
       │                │
       ▼                ▼
 PostgreSQL       Threat Intelligence
                      APIs
       │                │
       └───────┬────────┘
               ▼
          Final Report
               │
               ▼
          Web Dashboard
```

The **Analysis Engine** is currently implemented and performs the core technical analysis locally.

External threat-intelligence services will be used as additional evidence, not as the foundation of the analysis.

---


# 3. Target Validation

The platform accepts:

```text
IP address
Domain
Hostname
```

The system determines whether the submitted target is an IP address or a domain name before starting the analysis.

Examples:

```text
8.8.8.8
example.com
subdomain.example.com
```

Invalid or malformed targets will be rejected.

---

# 4. DNS Analysis

The platform currently performs DNS queries and collects relevant DNS information.

The implementation supports:

* A records
* AAAA records
* MX records
* NS records
* TXT records
* CNAME records
* Reverse DNS / PTR records

For domain targets, the scanner performs IPv4 and IPv6 resolution and queries the supported DNS record types.

Example:

```text
example.com

A
→ 93.184.216.34

MX
→ mail.example.com

NS
→ ns1.example.com
→ ns2.example.com
```

For IP targets, the scanner performs reverse DNS / PTR resolution.

The collected DNS information is stored in the scan results structure and will later be used by the detection engine and historical analysis.


### Planned detections

Examples of potential findings:

* Missing expected DNS records
* Suspicious DNS configuration
* Unexpected record changes
* Domain resolving to unexpected infrastructure
* Suspicious or unusual DNS characteristics

Detection rules will be implemented by the project rather than simply copied from an external service.

---

# 5. HTTP / HTTPS Analysis

The platform currently performs HTTP and HTTPS analysis against the submitted domain.

The scanner collects:

* HTTP status code
* Final/requested URL
* Redirect information
* HTTP Response headers
* Security-related headers
* HTTPS availability

Redirects are intentionally not automatically followed during the initial request, allowing the scanner to identify the returned Location header.

Examples:

```text
HTTP Status: 301
HTTPS: Available
Redirect: HTTP → HTTPS

Security Headers:

HSTS:        Present
CSP:         Present
X-Frame:     Present
X-Content:   Missing

The scanner currently checks the presence and value of:

Strict-Transport-Security
Content-Security-Policy
X-Frame-Options
X-Content-Type-Options
Referrer-Policy
Permissions-Policy

The collected HTTP information is stored in the scan results structure.
```

### Planned detections

Examples:

```text
[MEDIUM] HTTPS not enforced
[LOW] Missing security header
[LOW] Server information exposed
```

The detection engine will determine the severity of findings based on predefined security rules.

---

# 6. TLS Analysis

For HTTPS-enabled targets, the platform currently analyzes the TLS configuration.

The scanner collects:

* TLS version
* Cipher
* Cipher key size
* Certificate subject
* Certificate issuer
* Certificate validity period
* Certificate expiration date
* Subject Alternative Names (SANs)

Example:

```text
TLS Analysis

Protocol: TLSv1.3 
Cipher: TLS_AES_256_GCM_SHA384 
Key Size: 256 bits 

Certificate: 
Subject: www.example.com 
Issuer: Example CA 
Valid From: 2026-01-01 
Valid Until: 2027-01-01 
SANs: → www.example.com → example.com
```

The scanner currently focuses on collecting TLS information. Security validation and interpretation will be handled by the detection engine.

### Planned detections

Examples:

```text
[HIGH] Deprecated TLS version detected
[MEDIUM] Certificate expires soon
[HIGH] Certificate hostname mismatch
[HIGH] Invalid certificate
```

The detection logic will be implemented within the project's own analysis engine.

---

# 7. Network / Port Analysis

The scanner currently performs controlled TCP connectivity checks against a predefined set of common ports.

The initial implementation checks:

```text
21     FTP
22     SSH
23     Telnet
25     SMTP
53     DNS
80     HTTP
110    POP3
143    IMAP
443    HTTPS
445    SMB
3389   RDP
```

The scanner identifies whether a TCP connection appears:

```text
OPEN
CLOSED
FILTERED / UNREACHABLE
```

Example:

```text
Port Scan

22     OPEN
80     OPEN
443    OPEN
3389   FILTERED
```

The current implementation uses TCP connection attempts rather than a raw SYN scan.

The project will use controlled scanning and will only be used against systems for which the user has authorization.

### Planned detections

Examples:

```text
[MEDIUM] RDP exposed
[HIGH] Database service exposed
[MEDIUM] Telnet exposed
```

The detection engine will determine whether an exposed service represents a security finding based on the target and the configured detection rules.

--- 

# 8. Current Scan Data Structure

The scanner combines the results from the different analysis modules into a single structured object:

scan_results = {
    "target": name,
    "dns": dns_results,
    "http": http_results,
    "tls": tls_results,
    "ports": port_results
}

This structure provides the interface between the Analysis Engine and the future Detection Engine.

The separation is intentional:

Analysis Engine
      │
      │ Collect facts
      ▼
 scan_results
      │
      │ Analyze findings
      ▼
Detection Engine
      │
      ▼
Risk Assessment

The scanner is responsible for collecting technical information, while the detection engine will be responsible for interpreting that information according to security rules.

---

# 9. Detection Engine

Status: Implemented

The Detection Engine consumes the structured `scan_results` generated by the scanner and applies custom security detection rules.

The engine currently evaluates areas such as:

* TLS version
* Security headers
* Exposed services
* Certificate configuration
* HTTP/HTTPS security configuration

The Detection Engine converts raw scanner data into structured findings.

Each finding contains information such as:

* Rule ID
* Finding title
* Severity
* Description
* Evidence
* Recommendation

Example:

```text
Rule ID: TLS-001
Finding: Deprecated TLS Version
Severity: HIGH
Evidence: TLSv1.0
Recommendation: Disable deprecated TLS versions and use modern TLS configurations.
```

The Detection Engine is designed to separate **data collection** from **security interpretation**. The scanner collects technical information, while the Detection Engine determines whether that information represents a security finding.

---

# 10. Risk Assessment

Status: Implemented

The Risk Assessment module calculates an overall risk score based on the findings generated by the Detection Engine.

The current scoring model assigns different weights according to finding severity:

```text
CRITICAL = 40 points
HIGH     = 25 points
MEDIUM   = 15 points
LOW      = 2 points
INFO     = 0 points
```

The resulting score is mapped to a risk level:

```text
0–19    LOW
20–39   MODERATE
40–69   HIGH
70–100  CRITICAL
```

The scoring model is implemented as part of the project rather than relying entirely on an external risk-scoring service.

Example output:

```text
Risk Assessment:
--------------------
  Risk Score: 20/100
  Risk Level: MODERATE

  Findings Breakdown:
    Low: 20
    Medium: 0
    High: 0
    Critical: 0

Total: 20
```

The scoring model is intentionally project-specific and may be refined as additional detection rules and contextual analysis are introduced.

---

# 11. Historical Analysis

Status: In Progress

PostgreSQL has been integrated into the platform to persist scan results and risk assessments.

The current database contains a `scans` table storing:

* Target
* Scan timestamp
* Risk score
* Risk level
* Complete scan results

The raw scanner output is stored using PostgreSQL `JSONB`, allowing the platform to preserve the complete structure of DNS, HTTP, TLS and port analysis without immediately requiring a large relational schema.

Current architecture:

```text
Scanner
   │
   ▼
Scan Results
   │
   ├──────────────► Detection Engine
   │                     │
   │                     ▼
   │                  Findings
   │                     │
   │                     ▼
   │                Risk Assessment
   │                     │
   │                     ▼
   └────────────────► PostgreSQL
```

The database integration currently allows completed scans to be persisted and retrieved.

Future development will use this historical data to compare scans over time.

Example:

```text
Scan 1
  Port 443: OPEN
  Port 8080: CLOSED

        ↓

Scan 2
  Port 443: OPEN
  Port 8080: OPEN
```

The platform will then be able to identify changes such as:

* New port detected
* Port no longer accessible
* Certificate changed
* DNS record changed
* Security header removed
* TLS configuration changed
* Risk score increased or decreased
* New security finding detected
* Previous finding resolved

This will evolve the platform from a point-in-time scanner into a system capable of monitoring the security posture of a target over time.

---

# 12. Database & Configuration

The platform uses PostgreSQL for persistent storage.

Database:

```text
Database: security_intelligence
Table: scans
```

Python communicates with PostgreSQL through the `psycopg` driver.

Database credentials should not be hardcoded in the source code. They are provided through environment variables.

Example:

```text
DATABASE_HOST=localhost
DATABASE_NAME=security_intelligence
DATABASE_USER=security_platform
DATABASE_PASSWORD=your_password
```

The password must not be committed to the Git repository.

A local `.env` file can be used during development and should be added to `.gitignore`:

```text
.env
```

The project should load database configuration from environment variables rather than storing credentials directly inside `database.py`.

---

# 13. Threat Intelligence

Status: Planned

External threat-intelligence services will be used as additional evidence rather than replacing the platform's own analysis.

Potential integrations include:

AbuseIPDB
VirusTotal
GeoIP services

The architecture will therefore distinguish between:

Internal Analysis
       +
External Intelligence
       ↓
Combined Security Context

---

# 14. Web Dashboard

Status: Planned

The final platform will provide a web interface where analysts can submit targets and visualize scan results.

Potential functionality includes:

Target submission
Scan status
Security findings
Risk score
DNS information
HTTP/HTTPS information
TLS information
Open ports
Historical comparisons
Threat intelligence results

--- 

# 15. Containers and CI/CD

Status: Planned

The application will eventually be containerized using Docker and Docker Compose.

GitHub Actions will be used to implement CI/CD workflows such as:

Git Push
   ↓
GitHub Actions
   ↓
Tests
   ↓
Linting / Validation
   ↓
Build

---

# 16. Final Technology Stack

| Area                | Technology              |
| ------------------- | ----------------------- |
| Backend             | Python                  |
| API Framework       | FastAPI                 |
| Frontend            | HTML / CSS / JavaScript |
| Database            | PostgreSQL              |
| Network Analysis    | Python                  |
| DNS Analysis        | Python                  |
| HTTP Analysis       | Python                  |
| TLS Analysis        | Python                  |
| Threat Intelligence | External APIs           |
| Containers          | Docker / Docker Compose |
| Operating System    | Linux                   |
| Version Control     | Git / GitHub            |
| CI/CD               | GitHub Actions          |

---

# 17. Final Project Goal

The final product should be a small but functional cybersecurity platform capable of:

```text
                    TARGET
                       │
                       ▼
              ┌────────────────┐
              │ Automated Scan │
              └───────┬────────┘
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
      DNS          HTTP/TLS       NETWORK
       │              │              │
       └──────────────┼──────────────┘
                      ▼
             Detection Engine
                      │
                      ▼
                Risk Scoring
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
     Historical Data      Threat Intelligence
          │                       │
          └───────────┬───────────┘
                      ▼
                 Final Report
                      │
                      ▼
                 Web Dashboard
```

The project will demonstrate practical experience across cybersecurity, software development, databases, web technologies, networking, Linux, containerization, version control and CI/CD, while keeping the core focus on security analysis rather than simply consuming external APIs.
