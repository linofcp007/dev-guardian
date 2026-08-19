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

Análogo para Python (`AttributeError`), Go (`nil pointer`), etc.

Para JS/TS, a ferramenta `bug_hunt` já corre por default um pack próprio,
`configs/semgrep/bugfix-js.yml` — catorze regras hand-authored, cada uma com
um par de fixtures (uma que tem de disparar, uma parecida que não pode) —
cobrindo seis classes: race conditions (`floating-mutation`, uma chamada que
muta estado sem `await` dentro de função `async` — declarações, arrow
functions, métodos de classe/objeto; NÃO cobre function expressions async,
uma limitação do motor do Semgrep), null/undefined safety,
off-by-one, memory/resource leaks, error handling engolido, e dois edge
cases (`reduce` sem valor inicial, `parseInt` sem radix). "Broken happy
paths" fica de fora como padrão: é uma categoria de consequência, não uma
forma sintática — `floating-mutation` cobre a sua forma concreta mais comum
e mais nada a cobre.

Para Python, o `bug_hunt` corre também por default
`configs/semgrep/bugfix-py.yml` — dez regras hand-authored, cada uma com o seu
par de fixtures — cobrindo as mesmas seis classes: `bare except:` e `except:
pass`, `.objects.get()` sem guardar o `DoesNotExist`, dereference de `None`
vindo de `re.match(...)` e de `dict.get(...)`, `range(len(x) + 1)`, ficheiros
abertos sem context manager, corotinas `asyncio` criadas e descartadas, TOCTOU
entre `os.path.exists()` e `open()`, e N+1 de querysets Django. Estas regras
somam-se às 32 regras Python que o `p/r2c-bug-scan` já corre — nenhuma duplica
nenhuma delas, medido contra as fixtures.

Não cobrem um `await` esquecido numa `async def` do próprio projeto: essa regra
geral não é exprimível em Semgrep OSS, e só os primitivos `asyncio` nomeados são
apanhados. Para essa classe, leia o código.

A N+1 de querysets Django exige o queryset dentro do próprio cabeçalho do
`for` — `qs = Book.objects.all()` seguido de `for book in qs:` fica
silencioso, e essa forma ligada a variável é provavelmente a mais comum na
prática. O TOCTOU só reage a `os.path.exists`: `os.path.isfile`,
`os.path.isdir` e `pathlib.Path(p).exists()` ficam todos silenciosos. E o
dereference de `dict.get(...)` exclui clientes HTTP pela SUBSTRING do nome
do receiver, não pelo nome — qualquer receiver cujo nome CONTENHA `requests`,
`session`, `client`, `httpx`, `aiohttp` ou `urllib` é ignorado, por isso
`session_data`, `clients` e `urllib_cache` também são falsos negativos, não
só um dicionário chamado exatamente `client`.

Mais duas exclusões que produzem falsos negativos, e que interessam sobretudo
a si enquanto leitor do código: o `.objects.get()` só é marcado quando não
está guardado, e um `except Exception:` largo conta como guarda — por isso um
`get()` dentro de `except Exception: pass` fica silencioso aqui, embora seja
pior do que um `get()` sem guarda nenhuma (o engolir do erro é apanhado à
parte pela regra `except-pass`, mas nada liga as duas observações). E os
ficheiros abertos sem context manager nunca são marcados quando o destino é
um atributo: `self.handle = open(path)` é ignorado de propósito, porque o
`close()` costuma viver noutro método, fora do alcance de uma regra
sintática. Uma classe que nunca fecha mesmo o handle passa despercebida — e é
essa a forma mais comum de um leak de ficheiro de longa duração.

Duas ressalvas a levar a sério antes de confiar num resultado limpo: isto é
Semgrep OSS, que casa sintaxe, não faz dataflow — um null deref a duas
funções de distância do guard continua invisível a estas regras, que
encontram a forma que o bug toma, não uma prova de análise; e a camada
heurística (`WARNING`/`INFO` — ex. `floating-mutation`, que casa pelo nome
do método e por isso não distingue uma mutação real como `repo.save()` de
uma chamada sem relação que só partilha o nome, como `ctx.save()`, o push
síncrono de estado do Canvas 2D) produz falsos positivos por construção,
por isso não é `ERROR` e o `severity_min` de `bug_hunt` existe precisamente
para os filtrar.

Para Go, o `bug_hunt` corre também por default
`configs/semgrep/bugfix-go.yml` — dez regras hand-authored, cada uma com o seu
par de fixtures — cobrindo as mesmas seis classes: erro descartado com `_`,
retorno atribuído a `_`, ramo `if err != nil` vazio, type assertion sem a
forma `, ok`, `for i := 0; i <= len(xs)`, corpo de resposta HTTP nunca
fechado, ticker nunca parado, `Lock()` sem `defer Unlock()`, resultado de
`append` descartado, e escrita em mapa nil. É a linguagem com o maior buraco
no registo: o `p/r2c-bug-scan` só tem 5 regras Go e apenas 2 caem numa classe
de bug.

Não cobrem goroutines que ficam penduradas, nem a captura da variável do
ciclo. A segunda foi construída e verificada a funcionar, e depois excluída de
propósito: o Go 1.22 passou a dar a cada iteração a sua própria variável, e o
Semgrep não lê o `go.mod` para saber que versão o módulo declara — em código
moderno acusaria a forma correta. Para essas duas classes, leia o código.

Mais duas lacunas medidas nas próprias regras: a `lock-without-defer` casa
pelos nomes literais `Lock()`/`Unlock()`, não `RLock()`/`RUnlock()`, por isso
um read-lock de `sync.RWMutex` sem `defer` — um idioma comum em Go — fica
totalmente fora do seu alcance. E a `nil-map-write` só apanha um mapa
declarado localmente com `var`: um mapa nil que chega como parâmetro de
função, campo de struct, ou valor de retorno entra em panic da mesma forma ao
escrever e não é coberto — provavelmente a forma mais comum na prática real.

Para Java, o `bug_hunt` corre também por default
`configs/semgrep/bugfix-java.yml` — oito regras hand-authored, cada uma com o
seu par de fixtures — cobrindo as mesmas seis classes: catch vazio, catch que
só faz `printStackTrace()`, dereference de `map.get()`, `Optional.get()` sem
`isPresent()`, `for (int i = 0; i <= a.length; i++)`, stream aberto fora de um
try-with-resources, `SimpleDateFormat` num campo estático, e remoção de uma
coleção durante o for-each sobre ela própria. É a linguagem mais vazia no
registo: das 4 regras Java do `p/r2c-bug-scan`, nenhuma cai numa classe de bug.

Não cobrem a comparação de `Integer` com `==`. Essa regra foi tentada e
descartada: exprimi-la exige inferência de tipos que o Semgrep OSS não faz sem
compilar, e a tentativa acusava `v == null` e a comparação de primitivos. Para
essa classe, leia o código.

**Isto é só para JS/TS, Python, Go e Java.** Para as restantes linguagens desta secção —
C#, PHP, Ruby, Rust — a situação anterior mantém-se: o
pack que corre por default (`p/r2c-bug-scan`) só cobre estas classes para
Python e Go, os packs de linguagem opcionais (`p/javascript`, `p/typescript`,
etc., ligados via `include_language_packs`) são packs de segurança e não
acrescentam nenhuma, e nenhuma tem ainda um pack local próprio. O caminho
fiável para elas continua a ser o raciocínio guiado por modelo desta própria
skill — ficheiro a ficheiro pelas zonas críticas (secção 1) e os padrões e
fixes da secção 4 abaixo.

Mesmo em JS/TS, estas catorze regras não substituem esse raciocínio: apanham
formas sintáticas, não motivos. Usa-as como primeira passada — não como
veredicto final.

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
