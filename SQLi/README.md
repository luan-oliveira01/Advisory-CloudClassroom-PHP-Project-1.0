# 04 — SQL Injection em updatefaculty.php (parâmetro fid)

**CVSS v3.1 9.1 (Crítico)** · `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
CWE: CWE-89 · Arquivo(s): `updatefaculty.php`

O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

## Documentos desta vulnerabilidade
- [`REPORT.md`](REPORT.md) — relatório técnico completo detalhado (passo a passo)
- [`poc.sh`](poc.sh) — PoC funcional executável (não-destrutivo)
- [`VULDB.md`](VULDB.md) — modelo de submissão VulDB
- [`ADVISORY.md`](ADVISORY.md) — modelo de GitHub Security Advisory
- [`VENDOR-EMAIL.md`](VENDOR-EMAIL.md) — modelo de e-mail formal ao fornecedor
- [`NIST.md`](NIST.md) — relatório no formato NIST/NVD

> Executar PoC: `bash poc.sh` (alvo padrão embutido; passe `http://alvo:porta` como argumento).
