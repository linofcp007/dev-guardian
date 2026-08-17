---
name: guardian-bugfix
description: Find and fix implementation bugs — race conditions, null safety, edge cases, off-by-one, memory leaks, missing error handling. EN triggers — use when the user says "guardian fix", "find bugs", "this is broken", "why does it crash", "edge cases", "any race conditions?", "this leaks memory", "check the error handling", "test X fails", "flaky in production", "sometimes works sometimes not", "weird behaviour", "behaves strangely", "deadlock?", or describes unexpected behavior. PT triggers — usa quando pedirem "guardian fix", "encontra bugs", "isto está partido", "porque é que isto crasha", "edge cases", "tem race conditions?", "isto perde memória", "vê se o tratamento de erros está bem", "o teste X falha", "intermitente em produção", "às vezes funciona às vezes não", "isto comporta-se estranho", "comportamento esquisito", "tem deadlock?". ES triggers — úsala cuando pidan "guardian fix", "encuentra bugs", "esto está roto", "¿por qué se cae?", "casos límite", "¿tiene race conditions?", "esto pierde memoria", "revisa el manejo de errores", "el test X falla", "intermitente en producción", "a veces funciona a veces no", "se comporta raro", "comportamiento extraño", "¿tiene deadlock?". Trilingual EN/PT/ES — respond in the user's language.
---

# Guardian Bugfix

Detecção e correção de bugs de implementação. Foca em problemas que SAST genérico tende a não apanhar e que dependem de raciocínio sobre comportamento dinâmico.

## Tipos de bug que esta skill caça

1. **Null/undefined safety** — acesso a propriedades sem check, optional chaining em falta
2. **Race conditions** — concorrência mal sincronizada, await em falta, callbacks duplicados
3. **Off-by-one e boundary errors** — loops, slicing, indexação
4. **Resource leaks** — file handles, DB connections, event listeners, timers, subscriptions
5. **Error handling** — `try` sem `catch` significativo, errors engolidos, logging em falta
6. **Type coercion** — `==` em JS, comparações entre tipos diferentes, parsing de input
7. **Date/timezone bugs** — UTC vs local, DST, formato de parsing
8. **Encoding/decoding** — UTF-8/16, base64, URL encoding inconsistente
9. **Edge cases de input** — strings vazias, arrays vazios, valores negativos, Unicode estranho
10. **Caching staleness** — invalidação em falta, TTLs errados
11. **Pagination / cursor bugs** — perda ou duplicação de records
12. **State management** — closures com referências stale, mutação de props em React

## Fluxo

### 1. Definir o âmbito

Antes de mergulhar, pergunta:

- "Há um bug específico que viste?" — se sim, foca aí
- "Ou queres uma varredura geral?" — se sim, vai ficheiro a ficheiro pelas zonas críticas

Se há repro steps, pede-os. Reproduzir o bug primeiro é sempre mais rápido que adivinhar.

### 2. Estratégia: reproduzir → isolar → diagnosticar → corrigir

**Reproduzir**: garantir que vês o bug. Escreve um teste que falha, se possível.

**Isolar**: simplificar até teres o caso mínimo. Comenta código, mocka deps, reduz input.

**Diagnosticar**: usa logging, debugger, prints estratégicos. Lê o código com olhar de "o que pode dar errado aqui?" — não "isto parece bem".

**Corrigir**: aplica o fix mínimo necessário. Não refatora junto — isso vem depois (guardian-quality).

### 3. Estratégias de busca

#### Statically (sem correr)

Padrões a procurar (passar Semgrep com regras específicas):

```yaml
# Null deref em JS/TS
rules:
  - id: unchecked-property-access
    pattern: $X.$Y.$Z
    message: Possível null deref. Considera optional chaining ($X?.$Y?.$Z).
    severity: WARNING
    languages: [javascript, typescript]
```

Análogo para Python (`AttributeError`), Go (`nil pointer`), etc. Não existe (ainda) um pack de regras Semgrep pronto para JS/TS especificamente nestas classes de bug. A ferramenta `bug_hunt` já verificou isto: o pack que corre por default (`p/r2c-bug-scan`) tem regras de null-safety, off-by-one, race conditions, memory leaks e error handling engolido — mas quase todas para Python e Go, nenhuma para JS/TS; os packs de linguagem opcionais (`p/javascript`, `p/typescript`, etc., ligados via `include_language_packs`) são packs de segurança e não acrescentam nenhuma. Para JS/TS, o caminho fiável hoje é o raciocínio guiado por modelo desta própria skill — ficheiro a ficheiro pelas zonas críticas (secção 1) e os padrões e fixes da secção 4 abaixo — não uma automação Semgrep que ainda não cobre esta linguagem.

#### Dynamically (correr)

- Se há testes, corre-os com cobertura. Linhas não cobertas são suspeitas.
- Se a app dá crash recorrente, ativa logging detalhado e reproduz.
- Para race conditions, usa `--race` em Go, `pytest-asyncio` em Python, `-r` em Rust, etc.

### 4. Padrões comuns e fixes

#### Null safety

```js
// 🐛 Bug
const name = user.profile.name;

// ✅ Fix
const name = user?.profile?.name ?? "Anonymous";
```

#### Race condition em fetch

```js
// 🐛 Bug — última resposta nem sempre é o último request
useEffect(() => {
  fetch(`/api/search?q=${query}`).then(setResults);
}, [query]);

// ✅ Fix
useEffect(() => {
  let cancelled = false;
  fetch(`/api/search?q=${query}`).then(r => {
    if (!cancelled) setResults(r);
  });
  return () => { cancelled = true; };
}, [query]);
```

#### Resource leak — event listener

```js
// 🐛 Bug — listener fica para sempre
window.addEventListener('resize', onResize);

// ✅ Fix
useEffect(() => {
  window.addEventListener('resize', onResize);
  return () => window.removeEventListener('resize', onResize);
}, []);
```

#### Error swallow

```python
# 🐛 Bug
try:
    do_thing()
except Exception:
    pass

# ✅ Fix
try:
    do_thing()
except SpecificError as e:
    logger.exception("do_thing failed")
    # decide: retry, propagar, fallback?
```

### 5. Testes de regressão

Para cada bug corrigido, **escrever um teste que falharia sem o fix**. Isto é não-negociável — sem este teste, o bug volta. Se o framework de testes não está configurado, sugere setup mínimo (pytest para Python, vitest/jest para JS, etc.) e adiciona-o.

### 6. Fix automático vs sugestão

- **Aplicar automaticamente sem perguntar**: nunca.
- **Aplicar com confirmação**: fixes mecânicos óbvios (null check, await em falta, cleanup em useEffect).
- **Só sugerir**: tudo que envolve mudança de comportamento de negócio (mudar como pagamentos são processados, etc.) — escreve a sugestão clara mas o utilizador decide.

## Comportamento "intermitente"

Se o utilizador descreve algo intermitente ("às vezes funciona às vezes não"), as causas mais prováveis em ordem:

1. **Race condition** (mais comum)
2. **Dependência externa flaky** (rede, DB, API)
3. **Dados específicos** (input com algum char estranho, registo com null)
4. **Timezone / date** (à meia-noite tudo parte)
5. **Cache stale** (a 1ª request é OK, a 2ª não)
6. **Memória ou recursos** (corre OK no início, falha depois)

Aborda nesta ordem.

## Anti-padrões a evitar

- **Não adicionar try/catch só para silenciar** — isso esconde bugs futuros.
- **Não "consertar" alterando comportamento esperado** — primeiro confirma o que devia acontecer.
- **Não largar logs de debug no commit final** — usa logger configurável.
- **Não confiar em testes que tu acabaste de escrever sem ver falhar primeiro** — testa que o teste falha sem o fix.

## Integração com guardian-quality

Depois de corrigir bugs, sugere correr `guardian quality` para verificar que o fix não introduziu code smells e que o estilo bate certo com o resto do projeto.
