---
name: guardian-review
description: Deep code review before PR, merge, or deploy — combines security + bugfix + quality + tests/CI checks, senior-dev style. EN triggers — use when the user says "guardian review", "review before commit/PR/merge/deploy", "check this before I push", "I'm about to push", "I'm opening a PR", "before going to production", "release time", "is this ready?", "is it safe to merge?", "validate these changes". PT triggers — usa quando disserem "guardian review", "revê antes de commit/PR/merge/deploy", "verifica isto antes de enviar", "vou fazer push", "vou abrir PR", "antes de ir para produção", "vou fazer release", "isto está pronto?", "diz-me se está OK fazer merge", "valida estas alterações". ES triggers — úsala cuando digan "guardian review", "revisa antes de commit/PR/merge/despliegue", "comprueba esto antes de enviar", "voy a hacer push", "voy a abrir PR", "antes de ir a producción", "voy a hacer release", "¿está listo?", "¿es seguro hacer merge?", "valida estos cambios". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Review

Revisão de código holística antes de PR, merge ou deploy. Pensa nisto como um senior dev a fazer code review final — combina as várias dimensões (segurança, bugs, qualidade) com contexto do *que mudou* e *para onde vai*.

## Quando esta skill é a certa

- Antes de abrir Pull Request
- Antes de fazer merge para `main`/`master`
- Antes de deploy para produção
- Pre-tag de release
- Quando o utilizador diz "vou fazer push" e quer um sanity check

Para auditorias periódicas sem mudança específica, usa `guardian-security`, `guardian-quality`, etc.

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

**Correctness**
- [ ] Lógica de cada nova função faz sentido para o input descrito
- [ ] Edge cases óbvios cobertos (vazio, null, negativo, Unicode, muito grande)
- [ ] Não introduz race conditions / async bugs
- [ ] Tratamento de erros é específico, não genérico-engole-tudo

**Security**
- [ ] Nenhum secret no diff (chave, password, token, URL com credenciais)
- [ ] Input do utilizador é validado/sanitizado antes de DB, shell, HTML
- [ ] Autenticação/autorização aplicadas onde precisam
- [ ] Não desativa CSP, CORS, ou outras defesas sem justificação
- [ ] Não escreve a log dados sensíveis (PII, tokens)

**Tests**
- [ ] Há testes para o comportamento novo?
- [ ] Os testes existentes passam (`pytest`, `npm test`, etc.)
- [ ] Coverage do diff é razoável (idealmente ≥ 70% do código novo)
- [ ] Testes de regressão para bugs corrigidos no diff

**Quality**
- [ ] Funções pequenas, nomes claros
- [ ] Sem código comentado-out
- [ ] Sem `console.log`/`print` deixados de debug
- [ ] Imports usados
- [ ] Estilo consistente com o resto do projeto

**Dependencies**
- [ ] Se há `package.json`/`requirements.txt` no diff, novas deps são necessárias?
- [ ] Licenças compatíveis (sem GPL em projeto comercial não-GPL)?
- [ ] Sem `*` ou ranges abertos

**Migrations / breaking changes**
- [ ] Migrations DB são reversíveis e não fazem lock prolongado
- [ ] APIs públicas mudadas estão versionadas ou marcadas como breaking
- [ ] Configs novas têm default seguro
- [ ] Rollback plan é claro

**Documentation**
- [ ] README/docs atualizados se comportamento público mudou
- [ ] CHANGELOG entry se aplicável

**CI / Build**
- [ ] CI passa (verificar via git status / GitHub se conectado)
- [ ] Builds reproduzíveis (sem `latest` em base images)

### 3. Executar verificações automáticas

Em paralelo (não em série) corre o subset relevante das verificações:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/scan/review-scan.sh "$(git diff --name-only origin/main...HEAD)"
```

Este script corre Semgrep só nos ficheiros do diff, gitleaks só no diff, Trivy se `package*.json`/`requirements*.txt`/etc. mudaram, e testes só dos módulos afetados (quando suportado).

### 4. Apresentar veredito

Estrutura curta e directa:

```
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

Se o PR é só atualização de dependências:
- Analisa o changelog/release notes da versão nova
- Marca como **patch** (seguro), **minor** (provavelmente seguro), **major** (precisa verificação manual)
- Para majors, identifica breaking changes que afetem o teu código (procura usos das APIs alteradas)
- Verifica que os testes ainda passam após o update
- Sugere merge/hold/manual-review

### 6. Pre-deploy específicos

Se a invocação é pre-deploy (não só PR), adiciona:

- Verifica feature flags — alguma activa só em staging?
- Verifica env vars novos têm valores em produção
- Verifica migrations — backup feito? lock potencial?
- Verifica monitoring — alertas para o novo endpoint/feature?
- Verifica rollback — comando claro? smoke tests?

## Modo discussão vs aplicação

Por defeito, esta skill discute e propõe — não aplica mudanças automaticamente. Se o utilizador disser "aplica os fixes que disseres", aplica-os um a um, mostrando o diff antes de cada.

## Integração com chat tools

Se o utilizador trabalha com PR descriptions, oferece gerar um sumário para colar no PR:

```
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
