Aqui está o documento com a enumeração corrigida e a tradução para o inglês:

```markdown
# Advisory-CloudClassroom-PHP-Project-1.0
*Security Advisories & Vulnerability Reports*

This repository contains security reports, Proofs of Concept (PoC), and responsible disclosure documentation regarding vulnerabilities identified in the `updatefaculty.php` component.

---

## 🛠️ 1. Test Environment Setup

To set up the environment, download the target repository and build the lab using the following commands:

1. **Clone the target repository:**

```bash
git clone [https://github.com/mathurvishal/CloudClassroom-PHP-Project.git](https://github.com/mathurvishal/CloudClassroom-PHP-Project.git)

```

2. **Install dependencies (Docker):**

```bash
sudo apt update && sudo apt install docker.io -y

```

3. **Run the application in a Docker container:**

```bash
sudo docker run -d --name cloudclassroom-lab --restart=always -p 9292:80 bladscan/cloudclassroom-sqli:1.0

```

---

## 🔍 2. Subject of Study

By running the command below inside the directory containing the CloudClassroom repository, you can observe that the target file for analysis is highlighted (`updatefaculty.php`):

```bash
sudo docker run --rm -v $(pwd):/src returntocorp/semgrep semgrep scan --config=auto --no-git-ignore /src

```

---

## 📌 3. Vulnerability Summary

| ID | Vulnerability | File / Parameter | CVSS v3.1 | Severity | CWE |
| --- | --- | --- | --- | --- | --- |
| **01** | SQL Injection (UNION-based) | `updatefaculty.php` (`fid`) | 9.1 | 🔴 Critical | CWE-89 |
| **02** | Stored Cross-Site Scripting (XSS) | `updatefaculty.php` *(multiple)* | 6.1 | 🟡 Medium | CWE-79 |

---

## 🔍 4. Findings Detail

### 01. SQL Injection in `updatefaculty.php`

* **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (**9.1 - Critical**)
* **CWE:** CWE-89 (SQL Injection)
* **Affected Component:** `updatefaculty.php` (`fid` parameter)

**Description:**

The numeric parameter `fid` is received via HTTP request and directly interpolated into the `SELECT` SQL query without sanitization or the use of prepared statements. Because the interpolation occurs in a numeric context (without quotes), exploitation via `UNION SELECT` is possible. The original query exposes 9 columns, allowing unauthenticated extraction of sensitive data, including administrator credentials.

---

### 02. Stored XSS in `updatefaculty.php`

* **CVSS v3.1 Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (**6.1 - Medium**)
* **CWE:** CWE-79 (Cross-site Scripting)
* **Affected Component:** `updatefaculty.php` (`fname`, `faname`, `addrs`, `gender`, `city`, `pass` fields)

**Description:**

Data submitted through the form fields is stored directly into the database without prior sanitization. When rendering the administrative interface, the application displays this data inside the `value="..."` attribute of HTML input tags without applying proper HTML entity encoding. The `fname` field accepts up to 50 characters (sufficient to inject and execute arbitrary scripts within the context of the administrator's browser).

---

## 📁 5. Directory Structure

Each folder (`01-sqli` and `02-stored-xss`) contains the following standardized set of documents:

```text
├── 01-sqli/
│   ├── REPORT.md          # Full technical step-by-step report
│   ├── poc.sh             # Functional, non-destructive PoC script
│   ├── VULDB.md           # Submission template formatted for VulDB
│   ├── ADVISORY.md        # GitHub Security Advisory draft
│   ├── VENDOR-EMAIL.md    # Formal email draft for vendor disclosure
│   └── NIST.md            # Report following NVD / NIST standards
└── 02-stored-xss/
    ├── REPORT.md
    ├── poc.sh
    ├── VULDB.md
    ├── ADVISORY.md
    ├── VENDOR-EMAIL.md
    └── NIST.md

```

```

```
