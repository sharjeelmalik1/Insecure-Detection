# Bandit Security Scan Report

**Scan Date:** Auto-generated
**Tool:** [Bandit](https://bandit.readthedocs.io/) v1.9.x
**Scope:** `app/` and `exploits/` directories
**Command:** `python -m bandit -r app/ exploits/ -f screen`

---

## Summary

| Severity | Count |
|----------|-------|
| High     | 1     |
| Medium   | 3     |
| Low      | 4     |
| **Total**| **8** |

---

## Findings

### HIGH Severity

#### 1. B201 — Flask Debug Mode Enabled
- **File:** `app/vulnerable_app.py:150`
- **CWE:** [CWE-94](https://cwe.mitre.org/data/definitions/94.html) — Improper Control of Generation of Code
- **Description:** `app.run(debug=True)` exposes the Werkzeug debugger, which allows arbitrary code execution via the interactive console.
- **Remediation:** Set `debug=False` in production. Use environment variables to toggle debug mode.

---

### MEDIUM Severity

#### 2. B301 — Pickle Deserialization (pickle.loads)
- **File:** `exploits/pickle_payload.py:135`
- **CWE:** [CWE-502](https://cwe.mitre.org/data/definitions/502.html) — Deserialization of Untrusted Data
- **Description:** `pickle.loads()` can execute arbitrary code embedded in the serialized data. An attacker who controls the input can achieve Remote Code Execution.
- **Remediation:** Use `json.loads()` for data exchange. If pickle is required, use a restricted `Unpickler` with an allowlist.

#### 3. B301 — Pickle Deserialization (pickle.loads)
- **File:** `exploits/pickle_payload.py:140`
- **CWE:** [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- **Description:** Same as above — second instance of `pickle.loads()` on untrusted data.

#### 4. B506 — Unsafe YAML Load
- **File:** `exploits/yaml_payload.py:94`
- **CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation
- **Description:** `yaml.load()` with `FullLoader` allows instantiation of arbitrary Python objects via YAML tags like `!!python/object/apply`.
- **Remediation:** Use `yaml.safe_load()` which only allows basic YAML types.

---

### LOW Severity

#### 5. B403 — Import of pickle module
- **Files:** `app/vulnerable_app.py:15`, `exploits/pickle_payload.py:26`
- **CWE:** [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- **Description:** The `pickle` module import itself is flagged as a warning because it signals potential unsafe deserialization.

#### 6. B105 — Hardcoded Password String
- **Files:** `app/vulnerable_app.py:20`, `app/secure_app.py:24`
- **CWE:** [CWE-259](https://cwe.mitre.org/data/definitions/259.html) — Use of Hard-coded Password
- **Description:** `SECRET_KEY` is hardcoded in source code. In production, secrets should be loaded from environment variables or a secrets manager.

---

## Comparison: Vulnerable vs Secure App

| Check | `vulnerable_app.py` | `secure_app.py` |
|-------|---------------------|-----------------|
| pickle.loads() | Found (CRITICAL) | Not present |
| yaml.load() unsafe | Found (HIGH) | Not present |
| yaml.safe_load() | Not used | Used |
| json.loads() | Not used for sessions | Used for sessions |
| HMAC cookie signing | Not present | Implemented |
| Input validation | Not present | Implemented |
| debug=True | Present | Not present |

---

## How to Reproduce

```bash
# Run Bandit on the vulnerable app only
python -m bandit -r app/vulnerable_app.py -f screen

# Run Bandit on the secure app only (should show minimal issues)
python -m bandit -r app/secure_app.py -f screen

# Export as JSON for CI/CD integration
python -m bandit -r app/ -f json -o detection/bandit_results.json
```
