# Submissão VulDB — CloudClassroom-PHP-Project 1.0 — Stored XSS em updatefaculty.php

> Modelo para submeter em https://vuldb.com/?submit — preencha os campos no formulário correspondente.

**Title:** CloudClassroom-PHP-Project 1.0 updatefaculty.php fname, faname, addrs, gender, city, pass Stored / Persistent Cross-Site Scripting

| Campo VulDB | Valor |
|-------------|-------|
| Product | CloudClassroom-PHP-Project |
| Version | 1.0 |
| Vendor | Vishal Mathur |
| Vulnerability class | Stored / Persistent Cross-Site Scripting |
| Affected component | updatefaculty.php (Component) |
| Affected parameter/argument | fname, faname, addrs, gender, city, pass |
| Attack vector | Remote (Network) |
| Authentication | Nenhuma para injetar (via item 00) |
| CWE | CWE-79 |
| CVSS 3.1 Base | 6.1 |
| CVSS 3.1 Vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N |
| Exploit availability | Público (PoC incluído) |
| Countermeasure | Codificar toda saída dinâmica com `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` no contexto correto. |

## Description

A vulnerability was found in CloudClassroom-PHP-Project 1.0. It has been classified as **Médio**.
This issue affects the component `updatefaculty.php` via the argument `fname`.
Os campos `fname`, `faname`, `addrs`, `gender`, `city`, `pass` são persistidos sem sanitização e reexibidos em atributo `value="..."` sem HTML-encoding. FName é varchar(50) (comporta payloads completos). Tela administrativa → XSS no contexto do admin.

The manipulation leads to cross-site scripting. The attack may be initiated remotely.

## Technical Details / Proof of Concept

```bash
# ciclo não-destrutivo (captura->injeta->verifica->restaura):
python3 ../_lib/xss_poc.py "http://127.0.01:9292" "updatefaculty.php?..." \
  fname '"><svg onload=alert(1)>' --fields fname,faname,addrs,gender,city,pass
```

Observed evidence:

```
payload refletido SEM encoding: "><svg onload=alert(1)>
```

## Countermeasure

- Codificar toda saída dinâmica com `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` no contexto correto.
- Validar/limitar o conteúdo na entrada e usar Content-Security-Policy.
- Prepared statements na persistência (defesa em profundidade).

## Timeline

- 2026-08-02: Vulnerability discovered and confirmed (local lab).
- 2026-08-02: Advisory prepared / VulDB submission drafted.

## Credits

Researcher: oliveira.luanalmeida@gmail.com e ethical.hacker.tiagoredivo@gmail.com

