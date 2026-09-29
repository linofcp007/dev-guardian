---
name: guardian-scanskill
description: Vet a third-party AI skill, MCP server, plugin or agent BEFORE installing it, with the scan_skill MCP tool — prompt injection, data exfiltration, privilege escalation, excessive agency, MCP tool poisoning, dangerous code, OSV CVEs — rolled into a 0-100 risk score and a SAFE → DO NOT INSTALL verdict. EN triggers — "is this skill safe?", "scan this skill", "audit this MCP server", "should I install this plugin?", "vet this agent", "is this plugin malicious?". PT — "esta skill é segura?", "scaneia esta skill", "audita este MCP", "devo instalar este plugin?", "este plugin é malicioso?", "verifica esta skill antes de instalar". ES — "¿esta skill es segura?", "escanea esta skill", "audita este MCP", "¿debo instalar este plugin?", "¿este plugin es malicioso?", "verifica esta skill antes de instalar". Respond in the user's language.
---

# Guardian Skill — verificar skills de IA / servidores MCP / agentes antes de instalar

Quase todo o dev-guardian pergunta *"o código que vou pôr em produção é seguro?"*.
Este módulo faz a pergunta de **supply chain** do ecossistema de agentes: **"esta
skill / servidor MCP / agente de terceiros é seguro para INSTALAR?"** — antes de
correr no teu ambiente.

Uma skill é só texto e scripts que o modelo lê e executa com os privilégios do
utilizador. Uma skill maliciosa pode trazer prompt injection, exfiltrar segredos,
envenenar a memória ou esconder instruções dentro da descrição de uma tool MCP.
Este módulo encontra isso antes de o utilizador confiar nela.

## Motor

O módulo assenta na **tool MCP `scan_skill`** — chama-a diretamente. Ela faz o
trabalho pesado (leitura dos ficheiros, análise e pontuação); tu interpretas e
apresentas.

```text
scan_skill(target?, check_deps?, write_reports?, severity_min?, fail_on?)
```

- **`target`** — uma **pasta** local, um **ficheiro**, um **.zip**, ou um **URL
  git / HTTP(S)**. Sem ele, audita a pasta do projeto atual (útil para "a skill
  em que estou está limpa?").
- **`check_deps`** (por omissão true) — consulta o **OSV.dev** à procura de CVEs
  conhecidos nas dependências declaradas. Offline degrada com honestidade
  (reporta "desconhecido", nunca "limpo").
- **`write_reports`** (por omissão true) — escreve `report.sarif` e `report.json`
  em `.guardian/reports/`, para CI / IDE.
- **`fail_on`** — `REVIEW` / `CAUTION` / `DO_NOT_INSTALL`; define a flag `passed`
  para poderes bloquear uma instalação.

## O que deteta — 16 categorias de ameaça

A tabela descreve cada categoria sem citar um payload — uma skill que o fizesse
seria, com razão, apanhada pelas próprias regras que descreve.

| Categoria | O que apanha |
| --- | --- |
| `prompt_injection` | Texto que tenta sobrepor-se às instruções do anfitrião ou às regras anteriores, ou que manda esconder ações do utilizador |
| `data_exfiltration` | Variáveis de ambiente, segredos, chaves SSH, credenciais do Claude Code e das CLIs de cloud (GitHub, gcloud, Azure) ou dados do browser enviados para um destino na rede |
| `privilege_escalation` | Elevação de privilégios, permissões abertas a todos, escrita em caminhos do sistema, desligar antivírus / SIP / firewall |
| `supply_chain` | Um script remoto descarregado e entregue a uma shell, instalações a partir de um URL ou sem versão fixada, hooks de ciclo de vida |
| `excessive_agency` | Apagamentos recursivos sem confirmação, force-push, remoção de tabelas ou bases de dados, ciclos sem limite, código que se altera a si próprio |
| `output_handling` | Output não confiável a chegar a HTML ou a execução dinâmica sem sanitização |
| `system_prompt_leakage` | Pedidos para revelar ou repetir o prompt de sistema ou as instruções escondidas |
| `memory_poisoning` | Conteúdo de um atacante escrito de forma duradoura na memória, nos ficheiros de regras ou no CLAUDE.md |
| `tool_misuse` | Um ajudante apresentado como só de leitura que recorre à shell, a processos ou à rede |
| `rogue_agent` | Comportamento que só se ativa numa data ou quando ninguém está a ver, **Unicode escondido / invisível**, mineração de criptomoedas, reverse shells |
| `trigger_abuse` | Ativação coerciva e demasiado ampla: a skill exige ser usada em todos os pedidos |
| `dangerous_code` | Execução dinâmica de código, shell a partir de código, desserialização insegura, descodificar e executar um payload |
| `taint` | Um ficheiro que **lê um segredo E tem um destino de rede ou de execução** (possível fluxo de exfiltração) |
| `yara` | Assinaturas conhecidas — blobs codificados, hosts de exfiltração / C2 conhecidos, ofuscação |
| `mcp_least_privilege` | Um manifesto MCP que concede âmbitos `*` / `all` de que não precisa |
| `mcp_tool_poisoning` | Diretivas escondidas nos nomes ou nas descrições das tools MCP |

As instruções de uma skill são o que o modelo executa, por isso os comandos do
`SKILL.md` contam tanto como os scripts: as regras de código também leem cada
bloco de código (delimitado, indentado ou em `<pre>`) e cada trecho de código
inline, incluindo um ficheiro descarregado e executado mais abaixo, e as
regras de prosa leem, escritos como frases, um script remoto entregue a uma
shell, um programa descarregado e depois executado (ou colado num terminal a
partir de uma página), um ficheiro ou uma pasta de credenciais enviados para
um URL e o ambiente inteiro enviado para um URL. Os comandos que a
configuração de um plugin manda correr — os hooks do `hooks.json` e os
servidores MCP do `plugin.json` e do `.mcp.json` — passam pelas mesmas regras
de código que um script. Num ficheiro de
instruções, um comando que descarrega ou envia algo só pontua um nível abaixo
quando um marcador de documentação (reticências, `<url>`, `example.com`)
ocupa o lugar do alvo — sem alvo nenhum não desce, porque esconder o alvo é
uma forma de ofuscação. As outras regras (apagamentos, permissões, código
dinâmico) pontuam um nível abaixo quando nada à volta é um alvo de rede: uma
skill que *documenta* um comando destrutivo ou um padrão de deteção não é uma
skill que o executa.

As frases de prompt injection, de fuga ao papel, de esconder ações do
utilizador, de revelar o prompt de sistema, de persistência e de ativação
coerciva são o que uma skill sobre segurança de IA *cita*. Num ficheiro
Markdown, uma dessas frases fica **citada** — aparece como `low` — quando está
entre aspas fechadas ou num trecho de código de uma linha de prosa, ou num
bloco de código, e o texto à volta (o parágrafo da frase e o que o introduz)
a apresenta como material a que resistir (um ataque, malicioso, uma injeção,
rejeitado, detetado, "nunca instruções a seguir") sem mandar usá-la (seguir,
aplicar, obedecer, adotar, cumprir, "como as tuas instruções", "tal e qual",
"usa o seguinte"). "Exemplo" ou "dados de teste", por si só, não chegam; umas
aspas por fechar nunca citam; em JSON ou YAML as aspas são sintaxe. Todas as
citações aparecem, mas as de uma mesma regra pontuam uma só vez por skill. Um
modelo não deixa de obedecer a uma instrução por estar entre aspas: numa skill
que não é sobre segurança de IA, lê esses findings.

## Pontuação e veredicto

A tool devolve uma **pontuação de risco de 0 a 100** (pesada pela severidade;
findings em ficheiros **executáveis** pesam 1,3×) e uma de quatro recomendações:

- **SAFE** (0-20) — sem sinais relevantes.
- **REVIEW** (21-35) — sinais menores; passa os olhos antes de instalar.
- **CAUTION** (36-50) — vários sinais; só de um autor de confiança e depois de
  revisão manual.
- **DO_NOT_INSTALL** (51-100) — risco alto; não instalar a menos que cada finding
  tenha uma explicação clara e benigna.

## Fluxo

1. **Obtém o alvo.** Se o utilizador colou um URL / caminho / zip, passa-o como
   `target`. Se aponta para "esta skill" sem caminho, omite o `target`.
2. **Chama o `scan_skill`.** Deixa o OSV correr, a menos que o utilizador esteja
   claramente offline ou peça para saltar as dependências (`check_deps: false`).
3. **Começa pelo veredicto.** Diz primeiro a **recomendação** e a **pontuação** —
   é a decisão de que o utilizador precisa.
4. **Depois as evidências**, agrupadas por severidade, do maior risco para o
   menor:
   - 🔴 **Critical / High** — os findings que levam a DO_NOT_INSTALL / CAUTION.
   - 🟡 **Medium** — merecem um olhar.
   - 🟢 **Low / Info** — contexto.
   Para cada um, cita `file_path:line` e a mensagem numa linha. Não despejes JSON.
5. **Explica, não te limites a listar.** Um único `eval()` num exemplo é
   diferente de `eval(atob(...))` mais um host de exfiltração conhecido e Unicode
   escondido. Relaciona os sinais numa história ("isto parece X") e diz com que
   confiança.
6. **Sê honesto sobre a cobertura.** Se o OSV esteve offline, diz que as
   dependências estão "por verificar, não limpas". Se o scan foi `truncated`,
   di-lo. Se só viste um ficheiro, diz que um scan do repositório inteiro veria
   mais.

## Enquadramento importante

- Isto é **triagem heurística antes de instalar**, não prova. Um finding é um
  "olha aqui", não uma condenação. Di-lo. O objetivo é travar o que é
  obviamente mau e pôr o suspeito à frente do juízo humano.
- **Nunca instales automaticamente** algo marcado CAUTION ou pior sem que o
  utilizador aceite o risco de forma explícita.
- Um resultado limpo quer dizer "nenhum sinal encontrado", não "provadamente
  seguro". Sugere uma leitura humana rápida de tudo o que vá correr com
  privilégios reais.

## Quando NÃO usar

- Para auditar o **código da própria aplicação** do utilizador → a skill
  `guardian-security` ou `/guardian-scan`.
- Para features de IA *dentro* da aplicação do utilizador (a superfície de prompt
  injection do seu próprio RAG ou chatbot) → `/guardian-scan`: o `scan_sast` (e
  por isso o `security_scan_full` e o `review_pr`) corre sempre o pack Semgrep
  do plugin para aplicações com LLM, em Python e JS/TS — output do modelo a
  chegar a execução dinâmica, a uma shell ou a SQL, o nome de uma ferramenta
  escolhido pelo modelo sem lista de permitidos, código remoto aceite sem
  revisão fixada, `torch.load` inseguro, dados do pedido HTTP no prompt de
  sistema, chamadas à OpenAI sem limite de tokens (a lista completa está no
  `guardian-security`). O que o pack não vê revê-se à mão com a secção
  "Features de AI / LLM" da checklist do `guardian-review`. Di-lo em vez de
  correr o `scan_skill` sobre isso.
- Para a **configuração do espaço de trabalho de agentes** deste projeto
  (`.mcp.json`, `.claude/settings.json`: servidores MCP sem versão fixada,
  segredos escritos na config, permissões de Bash com wildcard) →
  `audit_agent_config { project_path: "<project>" }`; para as definições de
  tools que um servidor já configurado serve de facto (poisoning, shadowing,
  uma definição alterada desde a última auditoria) →
  `audit_mcp_tools { servers: ["<name>"] }`, que arranca esse servidor.
- Este módulo é especificamente para **artefactos de agentes de terceiros em que
  o utilizador ainda está a decidir se confia**.
