# IntelliVAPT — Comprehensive Master Technical Manual & Architectural Blueprint

---

# Table of Contents
1. [Project Overview & Core Mission](#1-project-overview--core-mission)
2. [End-to-End System Architecture](#2-end-to-end-system-architecture)
3. [Technology Stack & Dependency Breakdown](#3-technology-stack--dependency-breakdown)
4. [Complete File-by-File Technical Guide](#4-complete-file-by-file-technical-guide)
   - [4.1 Backend Engine (`backend/app/`)](#41-backend-engine-backendapp)
   - [4.2 Frontend Web App (`frontend/src/`)](#42-frontend-web-app-frontendsrc)
   - [4.3 Native Scanner Toolchain (`tools/bin/`)](#43-native-scanner-toolchain-toolsbin)
5. [Scanner Execution & Data Normalization Pipeline](#5-scanner-execution--data-normalization-pipeline)
6. [Security, Hardening & Defensive Architecture](#6-security-hardening--defensive-architecture)
7. [Database Schema & Data Model Specifications](#7-database-schema--data-model-specifications)
8. [API Endpoint Reference & Route Specifications](#8-api-endpoint-reference--route-specifications)
9. [UI/UX Workflows & Component Interactions](#9-uiux-workflows--component-interactions)
10. [Local Development, Deployment & Testing Guide](#10-local-development-deployment--testing-guide)

---

## 1. Project Overview & Core Mission

**IntelliVAPT** is an enterprise-ready **Vulnerability Assessment and Penetration Testing (VAPT)** automation platform designed to bridge the gap between low-level CLI security tooling and actionable executive reporting.

### Core Objectives:
* **Target Authorization & Scope Discipline:** Prevent accidental or out-of-scope scans by enforcing explicit authorization checks before any tool execution.
* **Automated Reconnaissance & Scanning:** Seamlessly orchestrate subdomain discovery, active HTTP probing, technology stack detection, and template-based vulnerability scanning in a single pipeline.
* **Attack Surface Visualization:** Model complex infrastructure topology and correlate findings to real host nodes in an interactive SVG graph.
* **End-to-End Remediation Tracking:** Enable security teams to track finding statuses (`OPEN`, `IN_PROGRESS`, `REMEDIATED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`) and save developer guidance notes.
* **Instant Deliverables:** Compile and automatically download executive PDF reports upon scan completion, alongside CSV and JSON exports for Jira / ticketing imports.
* **Native Windows Execution:** Operate natively using standalone Windows binaries (`.exe`) without needing WSL (Windows Subsystem for Linux) or Docker.

---

## 2. End-to-End System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          REACT 18 + VITE FRONTEND                           │
│                                                                             │
│   ┌──────────────────┐  ┌─────────────────────┐  ┌──────────────────────┐   │
│   │   AuthContext    │  │   ProjectContext    │  │     ToastContext     │   │
│   │  (JWT / Session) │  │ (State & Polling)   │  │  (Status Alerts)     │   │
│   └──────────────────┘  └─────────────────────┘  └──────────────────────┘   │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Views: Overview · Projects · Attack Surface · Assets · Findings   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / REST (Bearer JWT Auth)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            FASTAPI BACKEND CORE                             │
│                                                                             │
│  ┌─────────────────────────┐  ┌───────────────────┐  ┌───────────────────┐  │
│  │ Security Headers (ASGI) │  │ SlowAPI Limiter   │  │ Argon2 Password   │  │
│  │ CSP, Frame-Options      │  │ Brute-force Guard │  │ Cryptographic Hash│  │
│  └─────────────────────────┘  └───────────────────┘  └───────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ API Routers: /auth · /projects · /targets · /scans · /assets · /find  │  │
│  └───────────────────────────────────┬───────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Scanner Orchestrator (scanner.py) & Safe Subprocess Layer (services.py│  │
│  └───────────────────┬───────────────────────────────────┬───────────────┘  │
└──────────────────────┼───────────────────────────────────┼──────────────────┘
                       │                                   │
                       ▼                                   ▼
┌─────────────────────────────────────────┐ ┌─────────────────────────────────┐
│           SQLITE / POSTGRES             │ │     NATIVE WINDOWS TOOLCHAIN    │
│           (SQLAlchemy ORM)              │ │          (tools/bin/)           │
│                                         │ │                                 │
│  • Users & Audit Trail                  │ │  • subfinder.exe (DNS Recon)    │
│  • Projects & Scope Targets             │ │  • httpx.exe (Web Discovery)    │
│  • Assets & Normalized Vulnerabilities  │ │  • nuclei.exe (Vuln Scanner)    │
│  • Reports & Evidence POF Storage       │ │  • nmap.exe (Port Discovery)    │
└─────────────────────────────────────────┘ └─────────────────────────────────┘
```

---

## 3. Technology Stack & Dependency Breakdown

### Backend Stack
* **Language & Runtime:** Python 3.12+ (64-bit)
* **Web Framework:** FastAPI (High-performance ASGI framework)
* **Server:** Uvicorn (ASGI server with hot reload)
* **ORM & Database:** SQLAlchemy 2.0 with SQLite (`intellivapt.db`)
* **Security & Crypto:** `argon2-cffi` (Memory-hard password hashing) & `pyjwt` (Signed JWT bearer tokens)
* **Rate Limiting:** `slowapi` (Token bucket algorithm)
* **Report Generation:** `reportlab` (Dynamic PDF document compilation)
* **Data Validation:** `pydantic` v2 (Strict request/response validation)

### Frontend Stack
* **Framework:** React 18 with TypeScript
* **Build Tool:** Vite 8.2 (Instant hot module replacement)
* **Icons:** `lucide-react` (Vector icons)
* **Design System:** Bespoke Gruvbox dark theme palette (`#282828`, `#1d2021`, `#ebdbb2`, `#fe8019`, `#fb4934`, `#b8bb26`)

### Native Windows Toolchain
* **ProjectDiscovery Subfinder (v2.6.8):** Fast passive subdomain enumeration.
* **ProjectDiscovery HTTPX (v1.6.9):** Fast HTTP probe with status code, title, and technology detection.
* **ProjectDiscovery Nuclei (v3.3.7):** Template-based vulnerability scanner covering OWASP Top 10, CVEs, and misconfigurations.
* **Insecure Nmap (v7.92):** Standalone port discovery.

---

## 4. Complete File-by-File Technical Guide

### 4.1 Backend Engine (`backend/app/`)

#### `main.py`
The application factory. Creates the FastAPI instance, registers CORS middleware for `http://localhost:5173`, mounts the `SecurityHeadersMiddleware`, registers the `slowapi` rate limiter, includes all router endpoints from `app/routes/`, and creates SQLite tables on startup.

#### `scanner.py`
The multi-stage live scanner orchestrator. When a scan is triggered:
1. Spawns a background worker thread (`start_live_scan_thread`).
2. Reads in-scope targets, extracts the hostname, and validates it against a strict alphanumeric regex (`^[a-zA-Z0-9.\-_]+$`).
3. Invokes `subfinder.exe` to discover active subdomains.
4. Invokes `httpx.exe` to probe all responsive web services and extract status codes and web technologies.
5. Saves newly discovered services into the `Asset` table.
6. Invokes `nuclei.exe` across the target to execute vulnerability checks.
7. Parses JSON lines from Nuclei output and normalizes them into `Finding` records with CVSS scores, CWEs, CVEs, and remediation steps.
8. Updates scan progress to `100%` and status to `COMPLETED`.

#### `services.py`
The security execution boundary:
* `get_tool_binary(tool)`: Searches environment variables, system `PATH`, and `c:\D\Intelli_VAPT\tools\bin\{tool}.exe`.
* `safe_run(tool, arguments)`: Executes scanner binaries with `shell=False`, argument arrays, and input sanitization (rejecting null bytes `\x00` and arguments > 2048 characters).
* `tool_status()`: Queries installed tools and returns their discovery paths to the frontend.

#### `auth.py`
Handles password security and session authentication:
* `hasher`: Configured `PasswordHasher` using Argon2id.
* `create_access_token(user_id, role)`: Generates signed JWTs with 8-hour expiration.
* `current_user`: FastAPI dependency that validates the Bearer token against revoked tokens and fetches the `User` from the database.
* `require(*roles)`: Role-based access control guard.

#### `middleware.py`
Defensive request/response layers:
* `SecurityHeadersMiddleware`: Injects `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and a strict `Content-Security-Policy`.
* `register_rate_limiter()`: Attaches `slowapi` to protect against credential stuffing.

#### `models.py`
SQLAlchemy 2.0 database schema defining 8 ORM models: `User`, `Project`, `Target`, `Scan`, `Asset`, `Finding`, `Evidence`, `RemediationTask`, `Report`, and `AuditLog`.

#### `routes/` (Modular API Routers)
* `auth.py`: `/api/auth/register`, `/api/auth/login`, `/api/auth/logout`.
* `projects.py`: `/api/projects` (CRUD operations for projects).
* `targets.py`: `/api/projects/{id}/targets` (Add, delete, and toggle target exclusion).
* `scans.py`: `/api/projects/{id}/scans` (Queue scans, poll progress, read logs, cancel scans).
* `assets.py`: `/api/projects/{id}/assets` (List discovered host inventory).
* `findings.py`: `/api/projects/{id}/vulnerabilities` (List findings, edit remediation status, generate SVG attack-surface data).
* `reports.py`: `/api/projects/{id}/reports` (Generate ReportLab PDF and stream file downloads).
* `tools.py`: `/api/tools/status` (Health check of scanner binaries).

---

### 4.2 Frontend Web App (`frontend/src/`)

#### `context/ProjectContext.tsx`
The primary data hub. Stores the list of projects, selected project, targets, assets, findings, attack surface, and scan logs. Runs a 1-second polling timer during active scans. When a scan reaches `COMPLETED`, it automatically requests PDF generation and triggers an instant browser download.

#### `context/AuthContext.tsx`
Maintains user login state, JWT storage, user metadata, and logout operations.

#### `context/ToastContext.tsx`
Floating notification system that renders animated status toasts (success, error, info) without interrupting user flow.

#### `pages/Projects.tsx`
Project management console. Displays project summaries, launch scan button, active scan progress bar with live console logs, and target scope list with **Exclude/Include Scope** switches and target deletion.

#### `pages/Findings.tsx`
Vulnerability intelligence view. Features live text search, severity dropdown filters, status dropdown filters, **Export CSV**, **Export JSON**, and an **Edit** button opening the remediation modal.

#### `components/FindingModal.tsx`
Interactive dialog allowing analysts to change vulnerability status (`OPEN`, `IN_PROGRESS`, `REMEDIATED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`) and save fix guidance directly to the database.

#### `pages/Surface.tsx`
Renders an interactive SVG network topology diagram showing relationship links between the Internet ➔ Assets ➔ Vulnerabilities with color-coded nodes.

#### `pages/Overview.tsx`
Executive risk posture dashboard. Displays overall health metrics, vulnerability severity distribution bars, and recent project activity.

---

### 4.3 Native Scanner Toolchain (`tools/bin/`)

All binaries reside locally in `tools/bin/` and are detected automatically:
1. `tools/bin/subfinder.exe` (v2.6.8)
2. `tools/bin/httpx.exe` (v1.6.9)
3. `tools/bin/nuclei.exe` (v3.3.7)
4. `tools/bin/nmap.exe` (v7.92)

---

## 5. Scanner Execution & Data Normalization Pipeline

```
[User clicks "Launch Security Scan"]
              │
              ▼
[FastAPI Scans Router (/api/projects/{id}/scans)]
              │ Validates non-excluded targets in scope
              ▼
[Scanner Orchestrator: run_live_scan()]
              │
              ├─► 1. Subdomain Discovery (Subfinder)
              │      subfinder.exe -d <target> -silent
              │      Extracts: [sub1.target.com, api.target.com, ...]
              │
              ├─► 2. HTTP Probing & Tech Detection (HTTPX)
              │      httpx.exe -u <hosts> -status-code -title -tech-detect -json
              │      Saves to DB: Asset (hostname, http_status, technologies, title)
              │
              ├─► 3. Vulnerability Scanning (Nuclei)
              │      nuclei.exe -u https://<target> -silent -jsonl -severity low,med,high,crit
              │      Saves to DB: Finding (title, severity, cvss_score, cwe, cve, endpoint)
              │
              └─► 4. Scan Finalization & Auto-Report Trigger
                     Sets status = COMPLETED (100%)
                     Frontend triggers PDF generation and initiates download
```

---

## 6. Security, Hardening & Defensive Architecture

1. **No Command Injection:** All scanner invocations use `safe_run()` which passes arrays to `subprocess.run(shell=False)`.
2. **Flag Injection Defense:** Hostnames are strictly validated against `^[a-zA-Z0-9.\-_]+$` and cannot start with `-`.
3. **No SQL Injection:** 100% of database access is handled via parameterized SQLAlchemy 2.0 ORM models.
4. **No Path Traversal:** Report IDs are random UUIDs; reports are stored in a dedicated `./storage/reports/` directory with file validation.
5. **Brute Force Protection:** `slowapi` rate limits login (5 requests/minute) and registration (3 requests/minute).
6. **Password Security:** Hashes passwords with Argon2id (memory-hard, resistant to GPU/ASIC cracking).
7. **Defensive Headers:** Injects strict `Content-Security-Policy`, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.
8. **PDF Output Sanitization:** All text inputs are processed through `html.escape()` prior to ReportLab PDF rendering.

---

## 7. Database Schema & Data Model Specifications

```
  ┌─────────────────────────┐           ┌──────────────────────────┐
  │          users          │           │         projects         │
  ├─────────────────────────┤           ├──────────────────────────┤
  │ id (PK, String)         │1         *│ id (PK, String)          │
  │ email (Unique, String)  ├───────────┤ owner_id (FK -> users)   │
  │ password_hash (String)  │           │ name (String)            │
  │ role (Enum)             │           │ client (String)          │
  │ created_at (DateTime)   │           │ status (Enum)            │
  └─────────────────────────┘           └────────────┬─────────────┘
                                                     │ 1
                                                     │
                         ┌───────────────────────────┼───────────────────────────┐
                         │ *                         │ *                         │ *
           ┌─────────────▼────────────┐┌─────────────▼────────────┐┌─────────────▼────────────┐
           │         targets          ││          scans           ││          assets          │
           ├──────────────────────────┤├──────────────────────────┤├──────────────────────────┤
           │ id (PK, String)          ││ id (PK, String)          ││ id (PK, String)          │
           │ project_id (FK)          ││ project_id (FK)          ││ project_id (FK)          │
           │ value (String)           ││ status (Enum)            ││ hostname (String)        │
           │ target_type (String)     ││ profile (String)         ││ ip_address (String)      │
           │ excluded (Boolean)       ││ progress (Integer)       ││ http_status (Integer)    │
           └──────────────────────────┘│ log (Text)               ││ technologies (Text)      │
                                       └──────────────────────────┘└─────────────┬────────────┘
                                                                                 │ 1
                                                                                 │ *
                                                                   ┌─────────────▼────────────┐
                                                                   │     vulnerabilities      │
                                                                   ├──────────────────────────┤
                                                                   │ id (PK, String)          │
                                                                   │ project_id (FK)          │
                                                                   │ asset_id (FK)            │
                                                                   │ title (String)           │
                                                                   │ severity (String)        │
                                                                   │ cvss_score (Float)       │
                                                                   │ cwe (String)             │
                                                                   │ cve (String)             │
                                                                   │ finding_status (String)  │
                                                                   │ remediation (Text)       │
                                                                   └──────────────────────────┘
```

---

## 8. API Endpoint Reference & Route Specifications

| Method | Route | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/auth/register` | Register a new analyst account | Public (Rate-Limited) |
| `POST` | `/api/auth/login` | Authenticate and obtain JWT token | Public (Rate-Limited) |
| `POST` | `/api/auth/logout` | Revoke current JWT token | Bearer Token |
| `GET` | `/api/projects` | List all projects | Bearer Token |
| `POST` | `/api/projects` | Create a new project | Admin / Analyst |
| `DELETE`| `/api/projects/{id}` | Delete a project & its assets/findings | Admin / Analyst |
| `GET` | `/api/projects/{id}/targets` | List targets for a project | Bearer Token |
| `POST` | `/api/projects/{id}/targets` | Add an authorized target | Admin / Analyst |
| `DELETE`| `/api/projects/{id}/targets/{tid}` | Delete a target from scope | Admin / Analyst |
| `PATCH` | `/api/projects/{id}/targets/{tid}/toggle` | Toggle In-Scope / Excluded | Admin / Analyst |
| `POST` | `/api/projects/{id}/scans` | Queue a security scan | Admin / Analyst |
| `GET` | `/api/scans/{id}` | Poll scan progress & status | Bearer Token |
| `GET` | `/api/scans/{id}/logs` | Stream live scanner console logs | Bearer Token |
| `POST` | `/api/scans/{id}/cancel` | Cancel an active scan | Admin / Analyst |
| `GET` | `/api/projects/{id}/assets` | List discovered assets | Bearer Token |
| `GET` | `/api/projects/{id}/vulnerabilities` | List normalized findings | Bearer Token |
| `PATCH` | `/api/vulnerabilities/{id}` | Update remediation status & fix notes | Admin / Analyst |
| `GET` | `/api/projects/{id}/attack-surface` | Get graph nodes & edges for SVG map | Bearer Token |
| `POST` | `/api/projects/{id}/reports` | Generate a PDF report | Admin / Analyst |
| `GET` | `/api/reports/{id}/download` | Download compiled PDF report | Bearer Token |
| `GET` | `/api/tools/status` | Verify installed scanner binaries | Bearer Token |

---

## 9. UI/UX Workflows & Component Interactions

1. **Authentication Flow:** Users log in at `/login`. Successful login saves the JWT in memory and redirects to the **Assessment Dashboard**.
2. **Project Setup Flow:** The user clicks `+ New`, provides a project name and client, and adds an authorized domain (e.g. `example.com`).
3. **Scope Configuration:** Targets appear in a list. Analysts can exclude specific subdomains or delete targets before scanning.
4. **Live Scanning Flow:** Clicking `Launch Security Scan` starts the live assessment. Progress updates from 0% to 100% while console logs stream in real-time.
5. **Automatic Deliverable:** Once the scan reaches 100%, the browser automatically triggers the download of the PDF assessment report.
6. **Remediation & Export Flow:** On the Findings tab, analysts can search, filter by severity, export to CSV/JSON, or click `Edit` to update remediation status to `REMEDIATED`.

---

## 10. Local Development, Deployment & Testing Guide

### Starting the Platform
Open two PowerShell terminals:

```powershell
# Terminal 1: Backend API
cd C:\D\Intelli_VAPT\backend
uvicorn app.main:app --reload --port 8000
```
> Runs at `http://localhost:8000` (API Docs at `http://localhost:8000/docs`)

```powershell
# Terminal 2: Frontend Dashboard
cd C:\D\Intelli_VAPT\frontend
npm run dev
```
> Runs at `http://localhost:5173`

### Running the Test Suites
```powershell
# Run backend test suite
cd C:\D\Intelli_VAPT\backend
python -m pytest tests -v

# Run frontend TypeScript validation & build
cd C:\D\Intelli_VAPT\frontend
npm run build
```
