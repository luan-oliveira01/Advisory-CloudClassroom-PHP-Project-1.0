# CloudClassroom-PHP-Project 1.0 — Stored XSS em updatefaculty.php

## Descrição

CloudClassroom-PHP-Project 1.0 (Vishal Mathur, `mathurvishal`) contém uma vulnerabilidade de **Stored / Persistent Cross-Site Scripting** no componente `updatefaculty.php` através do(s) parâmetro(s) `fname`, `faname`, `addrs`, `gender`, `city`, `pass`. Os campos `fname`, `faname`, `addrs`, `gender`, `city`, `pass` são persistidos sem sanitização e reexibidos em atributo `value="..."` sem HTML-encoding. FName é varchar(50) (comporta payloads completos). Tela administrativa → XSS no contexto do admin.

Um atacante remoto pode explorar a falha enviando uma requisição HTTP `POST` manipulada ao endpoint afetado. Execução de JavaScript no contexto de administradores/professores autenticados: roubo de cookie de sessão, ações CSRF-como-vítima, pivô para tomada de conta administrativa.

## Componente afetado

| Campo | Valor |
|---|---|
| Produto | CloudClassroom-PHP-Project |
| Versão | 1.0 |
| Fornecedor | Vishal Mathur (`mathurvishal`) |
| Repositório | https://github.com/mathurvishal/CloudClassroom-PHP-Project |
| Arquivo(s) | `updatefaculty.php` |
| Parâmetro(s) | `fname`, `faname`, `addrs`, `gender`, `city`, `pass` |
| Método HTTP | POST |
| Autenticação exigida | Nenhuma para injetar (via item 00) |
| Interação do usuário | Requerida (vítima abre a página que renderiza o dado) |

## Classificação

- **Tipo:** Stored / Persistent Cross-Site Scripting
- **CWE:**
- CWE-79: Cross-site Scripting
- **OWASP:** A03:2021 – Injection
- **CVSS v3.1:** 6.1 (Médio) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

## Causa-raiz

**`updatefaculty.php`**

```php
<input ... name="fname" value="<?php echo $row[...]; ?>">
```

## Pré-condições

Nenhuma para injetar (item 00). Vítima autenticada (admin/faculty) precisa visualizar o registro.

## Impacto

Execução de JavaScript no contexto de administradores/professores autenticados: roubo de cookie de sessão, ações CSRF-como-vítima, pivô para tomada de conta administrativa.

## Prova de conceito

1. Enviar POST para `updatefaculty.php` gravando o payload de breakout no campo `fname`.
2. Payload: `"><svg onload=alert(1)>` (quebra o atributo value).
3. Abrir novamente a página; o payload é refletido SEM encoding e executa.
4. Encadear com o cookie sem HttpOnly (item 24) para roubo de sessão do admin.

```bash
# ciclo não-destrutivo (captura->injeta->verifica->restaura):
python3 ../_lib/xss_poc.py "http://127.0.0.1:9292" "updatefaculty.php?..." \
  fname '"><svg onload=alert(1)>' --fields fname,faname,addrs,gender,city,pass
```

**Evidência observada:** payload refletido SEM encoding: `"><svg onload=alert(1)>`

## Correção recomendada

- Codificar toda saída dinâmica com `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` no contexto correto.
- Validar/limitar o conteúdo na entrada e usar Content-Security-Policy.
- Prepared statements na persistência (defesa em profundidade).

## Estado de divulgação / CVE

Nenhuma CVE foi identificada para este componente/parâmetro no produto Vishal Mathur nem no código-base gêmeo 'CodeAstro Online Classroom' (verificado em NVD/cvefeed em 2026-08-02). Esta descrição destina-se à submissão para atribuição de CVE.

---
*Descrição gerada a partir de `_lib/findings_data.py` (fonte única). Produto: CloudClassroom-PHP-Project 1.0. Pesquisador: oliveira.luanalmeida@gmail.com.*
