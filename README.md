# Lightweight Web Security Scanner (Python)

A lightweight, opinionated web security reconnaissance scanner designed to quickly assess a target’s external attack surface using **HTTP analysis, TLS inspection, Nmap profiling, and heuristic CVE correlation**.

This tool is built for **early-stage assessments**, where speed, clarity, and low noise matter more than exhaustive coverage.

> ⚠️ **Legal Notice**  
> This tool is intended **only** for systems you own or have explicit authorization to test.

---

## Why This Exists

Most scanners fall into one of two extremes:

- **Enterprise-grade tools** that are powerful but heavy, noisy, and opaque  
- **Simple scripts** that are fast but narrowly focused

This project aims for the middle ground.

The goal is to answer questions a security engineer or attacker would ask *early* in an engagement:

- What stack am I talking to?
- Are obvious security controls missing?
- Is TLS configured safely?
- Are sensitive paths exposed?
- What does a careful Nmap scan reveal?
- Based on what I see, what known vulnerabilities should I research next?

The scanner prioritizes **signal over volume** and **context over verdicts**.

---

## Key Features

### 🔍 HTTP Fingerprinting
- Server and framework identification
- Security header analysis
- HTTP method discovery (`OPTIONS`, `TRACE`, etc.)
- Detection of exposed sensitive paths

### 🔐 TLS Inspection
- TLS protocol and cipher detection
- Certificate subject, issuer, and validity
- Basic weak-cipher identification

### 📡 Nmap Integration (Profile-Based)
Selectable scan profiles that reflect real-world tradeoffs:

- `normal` – standard service detection
- `stealth` – slower timing, scan delays
- `paranoid` – extremely cautious, low-noise scans
- `decoy` – advanced use only

Supports both:
- `python-nmap` (if installed)
- Native Nmap binary fallback

### 🧠 Heuristic CVE Correlation
- Extracts product/version hints from headers and Nmap output
- Queries the **CIRCL CVE API**
- Returns:
  - CVE ID
  - Short description
  - CVSS score (if available)
  - Publication date

> CVEs are **correlated, not confirmed**.  
> This step is about prioritization and research — not exploitation.

### 📄 Multiple Output Formats
- **HTML** – clean, readable reports
- **JSON** – automation and pipelines
- **Excel (XLSX)** – analyst and management-friendly

---

## Threat Model & Attacker Mindset

The scanner is intentionally designed around how attackers and experienced testers operate:

1. **Fingerprint quietly**
2. **Check misconfigurations before vulnerabilities**
3. **Confirm exposure, not just presence**
4. **Correlate versions to known weaknesses**
5. **Decide whether deeper effort is justified**

No payload fuzzing.  
No exploit attempts.  
No assumptions.

---

## Example Usage

Basic scan with HTML output:
```bash
python app.py https://example.com --output report.html
```

```bash
python app.py https://example.com \
  --output report.html \
  --nmap-profile stealth
```

```bash
python app.py example.com \
  --output report.json \
  --fast \
  --no-nmap
```