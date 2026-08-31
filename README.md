# IntelliVAPT — Automated Security Assessment Platform

A full-stack platform for **authorized Web Vulnerability Assessment and Penetration Testing (VAPT)**, attack-surface intelligence, and remediation tracking.

---

## 🚀 Quick Start

Start the Backend and Frontend in two separate terminals:

### **Terminal 1: Backend (FastAPI)**
```powershell
cd backend
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
* **API:** `http://localhost:8000`
* **API Docs:** `http://localhost:8000/docs`

### **Terminal 2: Frontend (React / Vite)**
```powershell
cd frontend
npm install
npm run dev
```
* **Web UI:** `http://localhost:5173`

---

## 🛠️ Security Scanners

Uses native Windows binaries in `tools/bin/`:

* **Subfinder** — Subdomain discovery
* **HTTPX** — Web service & technology detection
* **Nuclei** — Vulnerability & misconfiguration scanning
* **Nmap** — Port discovery

---

## 🛡️ Features

* **Target Scope Management:** Add, classify (`DOMAIN`, `IP`, `URL`, `CIDR`), include, or exclude targets.
* **Automated Assessment Pipeline:** Subdomain enumeration ➔ HTTP probing ➔ Vulnerability scanning.
* **Finding Lifecycle:** Update remediation statuses (`OPEN`, `IN_PROGRESS`, `REMEDIATED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`) and save fix notes.
* **Attack Surface:** Interactive SVG topology mapping.
* **Reports & Exports:** Automatic PDF reports, with one-click CSV and JSON exports.

---

## 🧪 Testing

```powershell
# Backend tests
cd backend
python -m pytest tests -v

# Frontend build check
cd ..\frontend
npm run build
```
