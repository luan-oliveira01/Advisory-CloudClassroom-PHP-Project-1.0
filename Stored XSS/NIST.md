# Vulnerability Report (formato NIST/NVD) — CloudClassroom-PHP-Project 1.0 — Stored XSS em updatefaculty.php

*Estruturado conforme convenções NIST SP 800-51 / NVD (CVE + CWE + CVSS v3.1 + CPE).*

## 1. Vulnerability Identification
- **Internal ID:** CC-2026-05
- **Proposed CVE:** (pendente de atribuição)
- **Report date:** 2026-08-02
- **Reporter:** oliveira.luanalmeida@gmail.com e ethical.hacker.tiagoredivo@gmail.com

## 2. Vulnerability Summary
Os campos `fname`, `faname`, `addrs`, `gender`, `city`, `pass` são persistidos sem sanitização e reexibidos em atributo `value="..."` sem HTML-encoding. FName é varchar(50) (comporta payloads completos). Tela administrativa → XSS no contexto do admin.

## 3. Weakness Enumeration (CWE)
- CWE-79: Cross-site Scripting

## 4. Affected Products (CPE 2.3)
- `cpe:2.3:a:vishalmathur:cloudclassroom-php_project:1.0:*:*:*:*:*:*:*`
- Vendor: Vishal Mathur · Product: CloudClassroom-PHP-Project · Version: 1.0
- Affected file(s): `updatefaculty.php`

## 5. Impact Metrics — CVSS v3.1
- **Base Score:** 6.1 (Médio)
- **Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

| Métrica | Valor |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | None (N) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Changed (C) |
| Confidentiality (C) | Low (L) |
| Integrity (I) | Low (L) |
| Availability (A) | None (N) |

- **EPSS:** N/A (sem CVE) — estimativa baixa.

## 6. Technical Description
Os campos `fname`, `faname`, `addrs`, `gender`, `city`, `pass` são persistidos sem sanitização e reexibidos em atributo `value="..."` sem HTML-encoding. FName é varchar(50) (comporta payloads completos). Tela administrativa → XSS no contexto do admin.

Causa-raiz:

**`updatefaculty.php`**

```php
<input ... name="fname" value="<?php echo $row[...]; ?>">
```

## 7. Attack Steps / Proof of Concept
1. Enviar POST para `updatefaculty.php` gravando o payload de breakout no campo `fname`.
2. Payload: `"><svg onload=alert(1)>` (quebra o atributo value).
3. Abrir novamente a página; o payload é refletido SEM encoding e executa.
4. Encadear com o cookie sem HttpOnly (item 24) para roubo de sessão do admin.

```bash
# ciclo não-destrutivo (captura->injeta->verifica->restaura):
python3 ../_lib/xss_poc.py "http://127.0.01:9292" "updatefaculty.php?..." \
  fname '"><svg onload=alert(1)>' --fields fname,faname,addrs,gender,city,pass
```

Evidence:
```
payload refletido SEM encoding: "><svg onload=alert(1)>
```

## 8. Impact Analysis
Execução de JavaScript no contexto de administradores/professores autenticados: roubo de cookie de sessão, ações CSRF-como-vítima, pivô para tomada de conta administrativa.

## 9. Recommended Mitigations
- Codificar toda saída dinâmica com `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` no contexto correto.
- Validar/limitar o conteúdo na entrada e usar Content-Security-Policy.
- Prepared statements na persistência (defesa em profundidade).

## 10. References
- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/

## 11. Disclosure Timeline
- 2026-08-02: Discovery and lab confirmation.
- 2026-08-02: Report drafted; coordinated disclosure initiated.
