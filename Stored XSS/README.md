# 05 — Stored XSS em updatefaculty.php

**CVSS v3.1 6.1 (Médio)** · `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
CWE: CWE-79 · Arquivo(s): `updatefaculty.php`

Os campos `fname`, `faname`, `addrs`, `gender`, `city`, `pass` são persistidos sem sanitização e reexibidos em atributo `value="..."` sem HTML-encoding. FName é varchar(50) (comporta payloads completos). Tela administrativa → XSS no contexto do admin.

## Documentos desta vulnerabilidade
- [`REPORT.md`](REPORT.md) — relatório técnico completo detalhado (passo a passo)
- [`poc.sh`](poc.sh) — PoC funcional executável (não-destrutivo)
- [`VULDB.md`](VULDB.md) — modelo de submissão VulDB
- [`ADVISORY.md`](ADVISORY.md) — modelo de GitHub Security Advisory
- [`VENDOR-EMAIL.md`](VENDOR-EMAIL.md) — modelo de e-mail formal ao fornecedor
- [`NIST.md`](NIST.md) — relatório no formato NIST/NVD

> Executar PoC: `bash poc.sh` (alvo padrão embutido; passe `http://alvo:porta` como argumento).
