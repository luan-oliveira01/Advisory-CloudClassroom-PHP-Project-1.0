# 16 — SQL Injection in viewquery.php (parameter eid)

**CVSS v3.1 9.1 (Critical)** · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
CWE: CWE-89 · File(s): `viewquery.php`

Parameter `eid` is interpolated in quotes in SELECT query. Closing the quote allows `UNION SELECT`. Target table exposes 4 columns. Confirmed with unauthenticated admin credential dump.

## Documents for this Vulnerability
- [`REPORT.md`](REPORT.md) — complete detailed technical report (step by step)
- [`poc.sh`](poc.sh) — functional executable PoC (non-destructive)
- [`VULDB.md`](VULDB.md) — VulDB submission template
- [`ADVISORY.md`](ADVISORY.md) — GitHub Security Advisory template
- [`VENDOR-EMAIL.md`](VENDOR-EMAIL.md) — formal vendor email template
- [`NIST.md`](NIST.md) — NIST/NVD format report

> Run PoC: `bash poc.sh` (default target embedded; pass `http://target:port` as argument).
