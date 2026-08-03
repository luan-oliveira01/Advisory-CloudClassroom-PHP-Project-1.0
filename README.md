```markdown
# Advisory-CloudClassroom-PHP-Project-1.0
*Security Advisories & Vulnerability Reports*

Este repositório contém os relatórios de segurança, Prova de Conceito (PoC) e documentações de divulgação responsável referentes às vulnerabilidades identificadas no componente `updatefaculty.php`.

---

## 🛠️ 1. Preparação do Ambiente de Testes

Para tal tarefa, realizo o download do repositório e a montagem do laboratório com os comandos abaixo:

1. **Clonar o repositório-alvo:**
   ```bash
   git clone [https://github.com/mathurvishal/CloudClassroom-PHP-Project.git](https://github.com/mathurvishal/CloudClassroom-PHP-Project.git)

```

2. **Instalar dependências (Docker):**
```bash
sudo apt update && sudo apt install docker.io -y

```


3. **Subir a aplicação em container Docker:**
```bash
sudo docker run -d --name cloudclassroom-lab --restart=always -p 9292:80 bladscan/cloudclassroom-sqli:1.0

```



---

## 🔍 2. Objeto de Estudo

Ao executar o comando abaixo no diretório em que se encontra o repositório do CloudClassroom, pode-se notar que o arquivo sugerido para análise é destacado (`updatefaculty.php`):

```bash
sudo docker run --rm -v $(pwd):/src returntocorp/semgrep semgrep scan --config=auto --no-git-ignore /src

```

---

## 📌 Resumo das Vulnerabilidades

| ID | Vulnerabilidade | Arquivo / Parâmetro | CVSS v3.1 | Severidade | CWE |
| --- | --- | --- | --- | --- | --- |
| **04** | SQL Injection (UNION-based) | `updatefaculty.php` (`fid`) | 9.1 | 🔴 Crítico | CWE-89 |
| **05** | Stored Cross-Site Scripting (XSS) | `updatefaculty.php` *(múltiplos)* | 6.1 | 🟡 Médio | CWE-79 |

---

## 🔍 Detalhamento dos Achados

### 04. SQL Injection em `updatefaculty.php`

* **Vetor de CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (**9.1 - Crítico**)
* **CWE:** CWE-89 (SQL Injection)
* **Componente Afetado:** `updatefaculty.php` (Parâmetro `fid`)

**Descrição:**

O parâmetro numérico `fid` é recebido via requisição HTTP e interpolado diretamente na consulta SQL `SELECT` sem sanitização ou uso de *prepared statements*. Como a interpolação ocorre em contexto numérico (sem aspas), é possível realizar exploração via `UNION SELECT`. A consulta de origem expõe 9 colunas, permitindo a extração não-autenticada de dados sensíveis, incluindo credenciais do administrador.

---

### 05. Stored XSS em `updatefaculty.php`

* **Vetor de CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (**6.1 - Médio**)
* **CWE:** CWE-79 (Cross-site Scripting)
* **Componente Afetado:** `updatefaculty.php` (Campos `fname`, `faname`, `addrs`, `gender`, `city`, `pass`)

**Descrição:**

Os dados enviados através dos campos do formulário são armazenados diretamente no banco de dados sem sanitização prévia. Ao renderizar a interface administrativa, a aplicação exibe esses dados no atributo `value="..."` de inputs HTML sem aplicar a devida codificação de caracteres (*HTML entity encoding*). O campo `fname` aceita até 50 caracteres (suficiente para injetar e executar scripts arbitrários no contexto do navegador do administrador).

---

## 📁 Estrutura de Arquivos

Cada pasta (`04-sqli` e `05-stored-xss`) contém o seguinte conjunto padronizado de documentos:

```text
├── 04-sqli/
│   ├── REPORT.md          # Relatório técnico completo e passo a passo
│   ├── poc.sh             # Script de PoC funcional e não-destrutivo
│   ├── VULDB.md           # Modelo de submissão formatado para a VulDB
│   ├── ADVISORY.md        # GitHub Security Advisory draft
│   ├── VENDOR-EMAIL.md    # Minuta de e-mail formal para comunicação ao desenvolvedor
│   └── NIST.md            # Relatório no padrão NVD / NIST
└── 05-stored-xss/
    ├── REPORT.md
    ├── poc.sh
    ├── VULDB.md
    ├── ADVISORY.md
    ├── VENDOR-EMAIL.md
    └── NIST.md

```

```

```
