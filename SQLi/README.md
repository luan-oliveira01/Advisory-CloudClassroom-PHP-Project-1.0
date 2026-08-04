# SQL Injection in updatefaculty.php (fid parameter)

**CVSS v3.1 9.1 (Critical)** · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
CWE: CWE-89 · File(s): `updatefaculty.php`

The `fid` parameter is interpolated without quotes (numeric context) into the SELECT query, allowing `UNION SELECT` exploitation. The queried table exposes 9 columns. Confirmed via unauthenticated dump of administrator credentials.

## Vulnerability Documentation
- [`REPORT.md`](REPORT.md) — complete, detailed technical report (step-by-step)
- [`poc.sh`](poc.sh) — executable functional PoC (non-destructive)
- [`VULDB.md`](VULDB.md) — VulDB submission template
- [`ADVISORY.md`](ADVISORY.md) — GitHub Security Advisory template
- [`VENDOR-EMAIL.md`](VENDOR-EMAIL.md) — formal vendor notification email template
- [`NIST.md`](NIST.md) — report formatted for NIST/NVD

> Run PoC: `bash poc.sh` (built-in default target; pass `http://target:port` as an argument).
