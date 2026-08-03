# Modelo de e-mail ao fornecedor — CloudClassroom-PHP-Project 1.0 — Stored XSS em updatefaculty.php

**Para:** Vishal Mathur (`mathurvishal`) — via GitHub Security Advisory privado do repositório, ou e-mail de contato do mantenedor
**De:** oliveira.luanalmeida@gmail.com e ethical.hacker.tiagoredivo@gmail.com
**Assunto:** [Security] CloudClassroom-PHP-Project 1.0 — Stored / Persistent Cross-Site Scripting em updatefaculty.php (CVSS 6.1)

---

Prezado(a) Vishal Mathur,

Meu nome é Luan Oliveira Ferreira de Almeida e conduzo pesquisa de segurança responsável. Durante uma avaliação do projeto **CloudClassroom-PHP-Project 1.0** (https://github.com/mathurvishal/CloudClassroom-PHP-Project), identifiquei uma vulnerabilidade de **Stored / Persistent Cross-Site Scripting** que gostaria de reportar de forma coordenada, antes de qualquer divulgação pública.

**Resumo técnico**
- Componente afetado: updatefaculty.php
- Parâmetro(s): fname, faname, addrs, gender, city, pass (POST)
- Classe / CWE: Stored / Persistent Cross-Site Scripting — CWE-79
- Severidade: CVSS v3.1 6.1 (Médio) — CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
- Autenticação necessária: Nenhuma para injetar (via item 00)

**Descrição**
Os campos `fname`, `faname`, `addrs`, `gender`, `city`, `pass` são persistidos sem sanitização e reexibidos em atributo `value="..."` sem HTML-encoding. FName é varchar(50) (comporta payloads completos). Tela administrativa → XSS no contexto do admin.

**Prova de conceito (ambiente de laboratório controlado)**
```
# ciclo não-destrutivo (captura->injeta->verifica->restaura):
python3 ../_lib/xss_poc.py "http://127.0.01:9292" "updatefaculty.php?..." \
  fname '"><svg onload=alert(1)>' --fields fname,faname,addrs,gender,city,pass
```
Evidência observada:
```
payload refletido SEM encoding: "><svg onload=alert(1)>
```

**Impacto**
Execução de JavaScript no contexto de administradores/professores autenticados: roubo de cookie de sessão, ações CSRF-como-vítima, pivô para tomada de conta administrativa.

**Correção recomendada**
- Codificar toda saída dinâmica com `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` no contexto correto.
- Validar/limitar o conteúdo na entrada e usar Content-Security-Policy.
- Prepared statements na persistência (defesa em profundidade).

**Divulgação coordenada**
Sigo uma política de divulgação responsável de 90 dias. Fico à disposição para esclarecer detalhes,
fornecer o PoC completo e validar a correção. Pretendo solicitar um CVE para esta questão; se preferir
coordenar a atribuição, por favor me avise.

Aguardo seu retorno e agradeço a atenção.

Atenciosamente,
Luan Oliveira Ferreira de Almeida
oliveira.luanalmeida@gmail.com
