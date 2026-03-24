# Detecting Insecure Deserialization in Python Web Applications

An educational security project that demonstrates **insecure deserialization vulnerabilities** in Python, how to **detect** them with static analysis, and how to **mitigate** them with secure coding practices.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [How the Vulnerabilities Work](#how-the-vulnerabilities-work)
3. [Project Structure](#project-structure)
4. [Setup & Installation](#setup--installation)
5. [Running the Vulnerable App](#running-the-vulnerable-app)
6. [Exploit Demonstrations](#exploit-demonstrations)
7. [Detection](#detection)
8. [Mitigation (Secure App)](#mitigation-secure-app)
9. [Before/After Comparison](#beforeafter-comparison)
10. [Tech Stack](#tech-stack)

---

## Project Overview

Insecure deserialization is ranked in the **OWASP Top 10** (A8:2017 / A08:2021). It occurs when an application deserializes data from untrusted sources using formats that can encode executable instructions — such as Python's `pickle` or PyYAML's unsafe loaders.

This project provides:

- A **vulnerable Flask app** with three exploitable endpoints
- **Exploit scripts** generating malicious pickle and YAML payloads
- An **AST-based static analysis scanner** that detects insecure patterns
- **Bandit integration** for automated security scanning
- A **secure Flask app** with all vulnerabilities fixed
- A **test suite** proving exploits work on the vulnerable app and are blocked on the secure app

> **Warning:** This project is for **educational purposes only**. Never deploy the vulnerable app on a public network.

---

## How the Vulnerabilities Work

### Pickle Deserialization (CWE-502)

Python's `pickle` module serializes objects by recording reconstruction instructions. The `__reduce__` method lets any object specify an **arbitrary callable** to invoke during `pickle.loads()`:

```python
class Malicious:
    def __reduce__(self):
        return (os.system, ("echo PWNED",))

# When the server calls pickle.loads(attacker_data), it runs os.system("echo PWNED")
```

**Attack vector:** The vulnerable app stores session data as a base64-encoded pickle cookie. An attacker replaces the cookie with a crafted payload to achieve Remote Code Execution (RCE).

### YAML Deserialization (CWE-20)

PyYAML supports Python-specific YAML tags that instantiate arbitrary objects:

```yaml
exploit: !!python/object/apply:os.system
  - "echo PWNED"
```

When parsed with `yaml.load(data, Loader=yaml.UnsafeLoader)`, PyYAML calls `os.system("echo PWNED")`.

**Attack vector:** The vulnerable app accepts raw YAML config via an API endpoint and parses it with an unsafe loader.

---

## Project Structure

```
project-root/
│
├── app/
│   ├── vulnerable_app.py   # Flask app with insecure deserialization
│   ├── secure_app.py        # Fixed version with mitigations
│   └── routes/
│
├── exploits/
│   ├── pickle_payload.py    # Pickle RCE payload generator
│   └── yaml_payload.py      # YAML exploit payload generator
│
├── detection/
│   ├── ast_scanner.py       # AST-based static analysis tool
│   ├── scan_results.json    # Scanner output (auto-generated)
│   └── bandit_report.md     # Bandit findings documentation
│
├── tests/
│   └── exploit_tests.py     # Before/after exploit test suite
│
├── requirements.txt
└── README.md
```

---

## Setup & Installation

```bash
# Clone the repository
git clone <repo-url>
cd Insecure-Detection

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Vulnerable App

```bash
# Start the vulnerable app on port 5000
python app/vulnerable_app.py
```

Available endpoints:

| Endpoint           | Method | Description                          |
|--------------------|--------|--------------------------------------|
| `/`                | GET    | Landing page with endpoint listing   |
| `/profile`         | GET    | Reads pickled session cookie (vuln)  |
| `/profile/update`  | POST   | Sets pickled session cookie (vuln)   |
| `/yaml/config`     | POST   | Parses YAML from request body (vuln) |
| `/api/data`        | POST   | Accepts pickled API payload (vuln)   |

---

## Exploit Demonstrations

### 1. Pickle RCE via Cookie

```bash
# Generate the payload
python exploits/pickle_payload.py

# Use the printed base64 payload with curl:
curl -b "session_data=<BASE64_PAYLOAD>" http://localhost:5000/profile
```

### 2. Pickle RCE via API Body

```bash
curl -X POST http://localhost:5000/api/data \
     -H "Content-Type: application/json" \
     -d '{"payload": "<BASE64_PAYLOAD>"}'
```

### 3. YAML Code Execution

```bash
# Execute os.system via YAML tag
curl -X POST http://localhost:5000/yaml/config \
     -H "Content-Type: text/plain" \
     -d 'exploit: !!python/object/apply:os.system ["echo PWNED_VIA_YAML"]'

# Leak hostname
curl -X POST http://localhost:5000/yaml/config \
     -H "Content-Type: text/plain" \
     -d 'hostname: !!python/object/apply:platform.node []'
```

### 4. Run Exploit Scripts Locally

```bash
python exploits/pickle_payload.py    # Generates payloads + local demo
python exploits/yaml_payload.py      # Demonstrates YAML parsing unsafe vs safe
```

---

## Detection

### AST Static Scanner

A custom scanner using Python's `ast` module to detect dangerous deserialization patterns:

```bash
python detection/ast_scanner.py app/ exploits/
```

**Detected patterns:**
- `pickle.loads()` / `pickle.load()` — CRITICAL
- `yaml.load()` without SafeLoader — HIGH
- `yaml.unsafe_load()` — CRITICAL
- `marshal.loads()` / `shelve.open()` — HIGH

Output includes file location, severity, description, and remediation for each finding. Results are also exported to `detection/scan_results.json`.

### Bandit Automated Scanning

```bash
# Screen output
python -m bandit -r app/ exploits/ -f screen

# JSON report for CI/CD
python -m bandit -r app/ -f json -o detection/bandit_results.json
```

See [detection/bandit_report.md](detection/bandit_report.md) for the full documented report.

---

## Mitigation (Secure App)

The secure app (`app/secure_app.py`) applies these fixes:

| Vulnerability | Mitigation |
|---------------|------------|
| `pickle.loads()` for sessions | Replaced with `json.loads()` + HMAC signing |
| `pickle.loads()` for API data | Replaced with native JSON parsing |
| `yaml.load(UnsafeLoader)` | Replaced with `yaml.safe_load()` |
| No input validation | Added sanitization + allowlist validation |
| No cookie integrity | Added HMAC-SHA256 cookie signing |
| No payload size limits | Added request body size checks |

```bash
# Start the secure app on port 5001
python app/secure_app.py
```

---

## Before/After Comparison

Run the full test suite to see exploits succeed on the vulnerable app and fail on the secure app:

```bash
# Run all tests with verbose output
python -m pytest tests/exploit_tests.py -v

# Run the comparison demo script
python tests/exploit_tests.py
```

**Expected results:**

| Test | Vulnerable App | Secure App |
|------|---------------|------------|
| Pickle RCE via cookie | Executes payload | Rejects (HMAC fails) |
| Pickle eval via API | Returns eval result | Returns raw string |
| Malicious YAML | Executes Python code | Blocked by safe_load |
| Benign YAML | Parses correctly | Parses correctly |
| Profile round-trip | Works (insecure) | Works (secure + signed) |
| Invalid role input | Accepted as-is | Rejected (default used) |

---

## Tech Stack

- **Python 3.11+**
- **Flask 3.x** — Web framework
- **PyYAML 6.x** — YAML parsing (demonstrates both safe and unsafe usage)
- **Bandit** — Automated Python security linter
- **ast** (stdlib) — Custom static analysis
- **pytest** — Test framework

---

## References

- [OWASP: Insecure Deserialization](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_Insecure_Deserialization)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Python pickle documentation — Security Warning](https://docs.python.org/3/library/pickle.html)
- [PyYAML Security Advisory](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation)
- [Bandit Documentation](https://bandit.readthedocs.io/)

---

> **Disclaimer:** This project is strictly for educational and authorized security testing purposes. The author is not responsible for misuse of the techniques demonstrated here.
