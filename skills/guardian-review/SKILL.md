---
name: guardian-review
description: Senior-style review of pending changes before a PR, merge or deploy — the review_pr MCP tool runs Semgrep, gitleaks, Bandit and Trivy on the diff, plus a scoped bug hunt and quality check, and a correctness / security / tests / migrations checklist, ending in a merge verdict. EN triggers — "review before PR / merge / deploy", "I'm opening a PR", "is this ready?", "is it safe to merge?", "validate these changes", "ship it or hold?". PT — "revê antes do PR / merge / deploy", "vou abrir PR", "isto está pronto?", "posso fazer merge?", "valida estas alterações", "avança ou espera?". ES — "revisa antes del PR / merge / despliegue", "voy a abrir un PR", "¿está listo?", "¿es seguro hacer merge?", "valida estos cambios", "¿lo lanzamos o esperamos?". Respond in the user's language.
---

# Guardian Review

Revisão de código holística antes de PR, merge ou deploy. Pensa nisto como um senior dev a fazer code review final — combina as várias dimensões (segurança, bugs, qualidade) com contexto do *que mudou* e *para onde vai*.

## Quando esta skill é a certa

- Antes de abrir Pull Request
- Antes de fazer merge para `main`/`master`
- Antes de deploy para produção
- Pre-tag de release
- Quando o utilizador diz "vou fazer push" e quer um sanity check

Para auditorias periódicas sem mudança específica, usa `guardian-security`, `guardian-quality`, etc. Para um scan rápido antes do push (sem a revisão), `/guardian-scan --unpushed`. Para confirmar que o humano percebe as decisões de domínio do diff, junta a skill `guardian-grill`.

## Fluxo

### 1. Determinar o diff a rever

Pergunta (ou infere):

- Diff vs `main`/`master`? (mais comum em PR)
- Diff vs último commit? (pre-commit)
- Diff vs última tag/release? (pre-deploy)

Comandos:

```bash
git diff origin/main...HEAD              # PR review
git diff --staged                        # pre-commit
git diff <last-tag>..HEAD                # pre-release
```

### 2. Checklist universal

Para cada PR, valida explicitamente:

#### Correctness

- [ ] Lógica de cada nova função faz sentido para o input descrito
- [ ] Edge cases óbvios cobertos (vazio, null, negativo, Unicode, muito grande)
- [ ] Não introduz race conditions / async bugs
- [ ] Tratamento de erros é específico, não genérico-engole-tudo

#### Security

- [ ] Nenhum secret no diff (chave, password, token, URL com credenciais)
- [ ] Input do utilizador é validado/sanitizado antes de DB, shell, HTML
- [ ] Autenticação/autorização aplicadas onde precisam
- [ ] Não desativa CSP, CORS, ou outras defesas sem justificação
- [ ] Não escreve a log dados sensíveis (PII, tokens)

#### Tests

- [ ] Há testes para o comportamento novo?
- [ ] Os testes existentes passam (`pytest`, `npm test`, etc.)
- [ ] Coverage do diff é razoável (idealmente ≥ 70% do código novo)
- [ ] Testes de regressão para bugs corrigidos no diff

#### Quality

- [ ] Funções pequenas, nomes claros
- [ ] Sem código comentado-out
- [ ] Sem `console.log`/`print` deixados de debug
- [ ] Imports usados
- [ ] Estilo consistente com o resto do projeto

#### Dependencies

- [ ] Se há `package.json`/`requirements.txt` no diff, novas deps são necessárias?
- [ ] Licenças compatíveis (sem GPL em projeto comercial não-GPL)?
- [ ] Sem `*` ou ranges abertos

#### Migrations / breaking changes

- [ ] Migrations DB são reversíveis e não fazem lock prolongado
- [ ] APIs públicas mudadas estão versionadas ou marcadas como breaking
- [ ] Configs novas têm default seguro
- [ ] Rollback plan é claro

#### Documentation

- [ ] README/docs atualizados se comportamento público mudou
- [ ] CHANGELOG entry se aplicável

#### CI / Build

- [ ] CI passa (verificar via git status / GitHub se conectado)
- [ ] Builds reproduzíveis (sem `latest` em base images)

### 3. Executar verificações automáticas

1. `review_pr { project_path: "<project>", base_ref: "<base>" }` — `base_ref` por omissão `origin/HEAD`, depois `main`, depois `master`; `head_ref` por omissão `HEAD`. Corre Semgrep (as mesmas regras do `scan_sast`) sobre cada ficheiro adicionado, modificado ou renomeado no diff, gitleaks sobre os commits do PR (`base..head`), Bandit sobre os `.py` alterados e Trivy se um manifesto de dependências mudou. Os ficheiros são lidos no `head` — da working tree se estiver em checkout, senão de um checkout temporário. Um ref que não existe é um erro, nunca "sem ficheiros alterados". `local_only: true` evita o registry do Semgrep.
2. Bugs e qualidade **só nos ficheiros do diff** (o `review_pr` não os corre), com o `head` em checkout:

   - `bug_hunt { project_path: "<project>", scope: { diff: { base: "<base>" } } }`
   - `quality_check { project_path: "<project>", scope: { diff: { base: "<base>" } } }`

   Para uma revisão pré-commit do que está staged, `scope: { diff: { staged: true } }` nos dois.

3. Testes e CI: **nenhuma tool corre os testes**. Corre tu a suite (ou os testes dos módulos afetados) e vê o estado da CI (`gh pr checks` quando há GitHub CLI). Não inventes um "testes passam" que não viste.

### 4. Apresentar veredito

Estrutura curta e directa:

```markdown
# Review: <branch> → main · <N> ficheiros · +<add> -<del>

## Veredito: 🟡 Aprovar com mudanças pequenas
(ou 🟢 Pronto para merge / 🔴 Não fazer merge)

## Bloqueadores 🔴
[Nenhum] ou [lista detalhada com fix sugerido]

## A corrigir antes de merge 🟡
- src/api/users.ts:42 — `password` está a ir para log. Remove ou redige.
- migrations/0042.sql — ADD COLUMN NOT NULL numa tabela grande sem default. Vai fazer lock.

## Nice to have (não bloqueia) 🟢
- Considera extrair helper de validação repetido em 3 sítios novos

## Bom trabalho ✨
- Cobertura subiu de 56% → 64% no módulo orders
- Migration tem rollback documentado
```

### 5. Conduta especial: PRs do Dependabot/Renovate

Se o PR é só atualização de dependências (detalhe na skill `guardian-deps`):

- Analisa o changelog/release notes da versão nova
- Marca como **patch** (seguro), **minor** (provavelmente seguro), **major** (precisa verificação manual)
- Para majors, identifica breaking changes que afetem o teu código (procura usos das APIs alteradas)
- Verifica que os testes ainda passam após o update
- Sugere merge/hold/manual-review

### 6. Pre-deploy específicos

Se a invocação é pre-deploy (não só PR), o gate completo é `/guardian-release predeploy`. Na revisão, adiciona:

- Verifica feature flags — alguma activa só em staging?
- Verifica env vars novos têm valores em produção
- Verifica migrations — backup feito? lock potencial?
- Verifica monitoring — alertas para o novo endpoint/feature?
- Verifica rollback — comando claro? smoke tests?

## Modo discussão vs aplicação

Por defeito, esta skill discute e propõe — não aplica mudanças automaticamente. Se o utilizador disser "aplica os fixes que disseres", aplica-os um a um, mostrando o diff antes de cada.

## Integração com chat tools

Se o utilizador trabalha com PR descriptions, oferece gerar um sumário para colar no PR:

```markdown
## What
<resumo em linguagem natural>

## Why
<motivo>

## Testing
<como foi testado>

## Risk
<bloqueio / mitigação / rollback>
```

## Não fazer

- Não aprovar sem ter visto os ficheiros — uma review "ok" às cegas é pior que nenhuma
- Não exigir 100% coverage — testar tudo é um anti-padrão
- Não nitpick estilo se há linter configurado — esse é trabalho do linter
- Não bloquear merge por mudanças que estão fora do scope do diff
