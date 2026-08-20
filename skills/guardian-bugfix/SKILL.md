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
`configs/semgrep/bugfix-js.yml` — treze regras hand-authored, cada uma com
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

#### A auditoria de 1.8.1, e os tiers que dela resultaram

O pack saiu na 1.6.0 e nunca tinha sido lido por ninguém além de quem o
escreveu. Uma auditoria independente escreveu ~600 linhas de JS/TS contra o
**texto** das regras — não contra a intenção delas — e encontrou ~40 falsos
positivos em 14 regras. A causa não foi uma coleção de enganos separados: era
estrutural. **Todas as fixtures tinham sido escritas por quem escreveu a
regra**, por isso cada uma testava a intenção do autor em vez daquilo a que o
padrão de facto se liga. Três exemplos do que isso escondia:

- `$A.find(...).$PROP` liga-se a **qualquer** método chamado `find`, e `$PROP`
  casa chamadas de método e não só leituras de propriedade. Nove reproduções,
  **zero verdadeiros positivos**: em qualquer backend Node com Mongoose ou com
  o driver do Mongo, e em qualquer página com jQuery, disparava em ERROR em
  praticamente todas as queries e aconselhava `?.` — conselho errado para um
  objeto Query, exatamente como a regra Java que aconselhava `getOrDefault`
  numa `List`.
- `floating-mutation` disparava em `res.send(rows)`, a linha mais comum de uma
  app Express, e em `void repo.save(a)` — **a correção que a sua própria
  mensagem prescreve**. 12 de 15 disparos eram falsos. Uma regra cuja correção
  prescrita não a cala ensina as pessoas a ignorá-la.
- `loop-lte-length` dizia a um ciclo que nunca indexa nada que "a última
  iteração lê `$A[$A.length]`". A mensagem era uma afirmação sobre código que
  não existia.

O que mudou nas três: a `unchecked-find` exige agora que o argumento seja um
**callback literal**, que é a única coisa que separa `Array#find` de uma Query
Mongoose (objeto), de um seletor jQuery (string) ou do `find(fn, ctx,
notSetValue)` do Immutable (três argumentos), sem inferência de tipos; a
`floating-mutation` exige que **o nome do recetor** também pareça uma fronteira
de persistência, e exclui `void`, `Promise.all`, continuação com
`.catch`/`.then`/`.finally` e capturar-para-esperar-depois; e a
`loop-lte-length` casa agora a **leitura** fora de alcance em vez do cabeçalho
do ciclo, o que torna a mensagem verdadeira por construção e ainda apanha o
corpo sem chavetas, que era invisível.

#### O self-scan, e as duas coisas que ele decidiu e o corpus não podia

Depois da auditoria, o pack foi corrido contra o **próprio `mcp/src` deste
repositório** — 183 ficheiros de TypeScript real que ninguém escreveu como
fixture, escolhidos nem por quem escreveu as regras nem pelo auditor. É uma
verificação barata, não precisa de fixture nenhuma, e apanhou duas coisas que
36 ablações em dois eixos não apanharam — porque "a cláusula está viva" e "não
reduz verdadeiros positivos" são **ambas verdadeiras** para uma cláusula que só
acrescenta falsos positivos:

- a `floating-mutation` passou de **20 findings a 0**. A correção a funcionar
  exatamente como pretendido, em código que nenhum de nós escolheu;
- a `unchecked-match` passou de **0 a 13** — uma regressão introduzida pela
  própria ronda de auditoria: o ramo `exec` novo não herdou a exclusão de
  optional chaining que o ramo `match` já tinha. Comprou um verdadeiro positivo
  e abriu duas formas de falso positivo; os 13 eram todos `exec(...)?.[1]`,
  código correto. Corrigido, com os near-misses em
  `misses/unchecked-match.ts`.

E decidiu duas coisas que o raciocínio sozinho não tinha decidido:

**A `catch-returns-null` foi apagada.** 25 findings em `mcp/src`, todos código
correto — o helper de `JSON.parse` seguro, um `readdirSync` com fallback `[]`,
um `getJson` com fallback `[]` — somados aos cinco do corpus da auditoria e a
zero verdadeiros positivos em qualquer dos dois. `INFO` não é um tier para uma
regra que nunca teve razão: é uma maneira mais silenciosa de continuar errada,
e continua a custar a quem lê o output. Devolver um valor vazio de um catch é
um idioma documentado de JavaScript, não uma forma de defeito, e não existe
discriminador sintático entre o idioma e um erro perdido.

**A `empty-catch` e a `empty-promise-catch` passaram de `ERROR` a `WARNING`.**
Produzem **45 findings em `mcp/src` e os 45 são fail-open deliberado e
documentado por comentário** — `catch { }` com um comentário a dizer que o
processo já morreu, que o handle já estava fechado, que a limpeza é best-effort.
Estavam em ERROR com o argumento de que um erro engolido **sem marcação** é um
bug seja qual for a intenção. O self-scan refuta a **premissa**, não a
conclusão: estão marcados. Estão marcados com um **comentário**, que o Semgrep
não lê. Uma declaração de intenção que a regra não consegue reconhecer é
exatamente o critério.

É o mesmo raciocínio que mantém a `empty-catch` **do Java** em `ERROR`, e não
uma contradição dele: a regra Java passa o critério porque **consegue** ler o
marcador de intenção do seu ecossistema — a convenção Checkstyle/IntelliJ de
chamar ao binding `ignore`/`ignored`/`expected`. JS/TS não tem equivalente com
o mesmo peso, e a razão é estrutural e não cultural: **o optional catch binding
do ES2019 tirou o identificador a que uma convenção de nomes se agarraria.** 41
dos 42 estão escritos `catch {`, sem nada para nomear. O ecossistema marca a
intenção com um comentário (ilegível aqui) ou com o `allowEmptyCatch` do
`no-empty` do ESLint, que é configuração de projeto e não um marcador no
código. O mais próximo que **é** legível por máquina passou a ser honrado na
mesma — um binding chamado `_`/`_e`/`_err` (o `caughtErrorsIgnorePattern` do
ESLint e a convenção do underscore do TypeScript) ou uma das três palavras do
Checkstyle — para que dar um caso por deliberado não obrigue a `// nosemgrep`.
Medido e dito em vez de insinuado: **removeu zero dos 42.**

**Uma regra está em `ERROR`: a `index-at-length`. Onze estão em `WARNING`, uma
em `INFO`.** O critério é o mesmo do pack Java, aplicado a frio:

> **Aquilo que a regra emite é sempre um bug?**

Passa uma: a `index-at-length`, porque uma **leitura** em `a[a.length]` é
incondicionalmente `undefined` — um facto sobre a AST e não uma guarda — e
porque produz **zero** findings em `mcp/src`, que é o número certo para uma
regra tão estreita.

Isto tem consequências a jusante, e são as mesmas do pack Java: o parser mapeia
ERROR → `high`, WARNING → `medium`, INFO → `info`, e o `create_fix_pr` assume
`severity_min: high`. Com uma regra em ERROR, o pack JS/TS quase não contribui
para o conjunto de fix-PR **por omissão** — e é esse o objetivo: uma corrida
por omissão não pode abrir um PR a reescrever 45 handlers de fail-open
deliberado. Quem quer estes bugs corrigidos pede `severity_min: "medium"`. O
`bug_hunt` em si não filtra nada, por isso nada desaparece de um scan.

Limitações medidas e **aceites**, nesta ronda, cada uma reproduzida contra o
corpus da auditoria:

| # | Dir | Regra | Código em que erra | Porque fica |
| --- | --- | --- | --- | --- |
| 1 | FP | `empty-catch`, `empty-promise-catch` | Fail-open deliberado marcado por **comentário**: `catch { }` com "// já morreu", "// best effort". **45 em 45** no `mcp/src` deste repositório | O Semgrep não lê comentários, e o optional catch binding do ES2019 tirou o identificador a que uma convenção de nomes se agarraria. É a razão declarada de ambas terem descido a `WARNING`; a saída `_`/`ignored` existe mas removeu zero dos 42. |
| 2 | **FN** | `unchecked-find` | Predicado **nomeado**: `users.find(byId).name` | Um argumento que é só um identificador é exatamente o que uma variável de query Mongoose também é. Aceitar identificadores reabre as nove reproduções. |
| 3 | **FN** | `floating-mutation` | Repositório cuja variável não tem nome de repositório; `const p = repo.save(a)` nunca esperado | O preço de não acusar todas as rotas Express do mundo, e de tratar capturar a promise como ato deliberado. |
| 4 | **FN** | `loop-lte-length` | `while` / `do-while`, `i < a.length + 1`, comprimento em cache (`const n = a.length`), acesso por método (`s.charAt(i)`) | Formas diferentes de AST; a de cache exige dataflow. A forma em cache é a que se escreve em hot paths, e é a lacuna mais cara desta lista. |
| 5 | FP | `unchecked-match` | Colisão de nome: `matcher.match(url)[0]` num objeto que devolve `string[]` | O único discriminador seria exigir um literal regex como argumento, e isso cala também `s.match(re)[1]` e a fixture que constrói o padrão a partir de config. Medido: custa mais verdadeiros positivos do que remove falsos. |
| 6 | FP | `unchecked-match`, `unchecked-find`, `reduce-without-initial` | Guarda a montante: `if (!re.test(s)) return '';`, `if (users.some(p))`, `if (xs.length === 0) return 0;` | É dataflow. É a razão declarada de estas três estarem em `WARNING`. |
| 7 | **FN** | `listener-without-cleanup`, `subscribe-without-unsubscribe` | Cleanup que **não remove nada** (`return () => {};`); e um segundo registo por limpar ao lado de um limpo no mesmo efeito | O `pattern-not-inside` não se consegue tornar relativo à **ocorrência** que está a julgar, só ao nó que a contém. A ordem exigida fecha a supressão por ramo, mas não esta. |
| 8 | **FN** | `listener-without-cleanup`, `subscribe-without-unsubscribe` | Ciclos de vida que não são `useEffect`: `componentDidMount`, `ngOnInit`, `onMounted`, `onMount`, `useLayoutEffect`; e `emitter.on(...)` | Sem a âncora do `useEffect` as duas regras disparariam em **todos** os registos de listener e subscrições de qualquer codebase — provado por mutação: apagar a cláusula produz 5 falsos positivos nas fixtures. |
| 9 | FP | `empty-catch` | Catch cujo corpo é só um **comentário** a explicar o ignore deliberado | Comentários não são nós da AST. A saída é o `// nosemgrep` do próprio Semgrep. |
| 10 | **FN** | `interval-without-clear` | Cleanup registado por callback que a regra não segue: `registry.add(() => clearInterval(t))` a uma profundidade que a elipse de bloco não alcança | Alargar a elipse alcançaria também closures sem relação e apagaria a regra. |

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

Duas regras Java restringem o recetor pelo **tipo declarado**, e isso troca
recall por precisão de propósito. O `metavariable-type` casa o tipo declarado
exato, sem subtipagem — medido: `type: List` **não** casa uma
`CopyOnWriteArrayList`, e é isso que mantém a `modify-during-iteration`
afastada dela. O custo: a `map-get-deref` enumera `Map`, `HashMap`, `TreeMap`,
`LinkedHashMap` e `ConcurrentHashMap`, por isso um mapa atrás de uma interface
do próprio projeto ou de um parâmetro de tipo genérico
(`<M extends Map<K,V>> … m.get(k).f()`) fica silencioso — um `Map` cru continua
a disparar, medido; e a `modify-during-iteration` enumera `List`, `ArrayList`,
`LinkedList`, `Set`, `HashSet`, `LinkedHashSet` e `Collection`, por isso um
`Deque`, uma `Queue`, um `SortedSet` ou uma coleção do próprio projeto ficam
silenciosos — e um `EnumMap` fica de fora da enumeração da `map-get-deref` pela
mesma razão.

As duas ligam o recetor por um `metavariable-pattern` que aceita um nome
simples **ou** um qualificado com `this.`. Antes disso, `cache.get(k).trim()`
disparava e `this.cache.get(k).trim()` era invisível — mesma classe, mesmo
campo, mesmo bug (medido).

A `map-get-deref` vinha **sem uma única exclusão de guarda**, e o resultado é
que a guarda canónica de Java disparava em ERROR a aconselhar `getOrDefault`
sobre código já guardado:

```java
if (m.containsKey(k)) { return m.get(k).trim(); }   // disparava, e é correto
```

Passou a excluir as formas medidas em que a chave fica provada presente:

- os testes inline `containsKey` e `get() != null` **na condição de um `if`**
  (sozinhos ou como qualquer dos operandos de uma **conjunção**), com o deref
  no ramo **verdadeiro**, com ou sem chavetas;
- `while (m.containsKey(k))`;
- os mesmos dois testes usados como **expressão** e não como condição de coisa
  nenhuma — `return m.containsKey(k) && m.get(k).isEmpty();`, ou atribuído a um
  local — e as suas duais de De Morgan, `!m.containsKey(k) || …` e
  `m.get(k) == null || …`, em que o `||` faz curto-circuito e o operando
  direito só corre quando a chave **está** presente;
- qualquer uma dessas quatro formas numa **cadeia**, com outra coisa a fazer
  curto-circuito à frente da guarda — `flag && m.containsKey(k) &&
  m.get(k).isEmpty()`, `flag || !m.containsKey(k) || m.get(k).isEmpty()`. Uma
  cláusula por guarda chega para cadeias de **qualquer comprimento**, porque o
  `$X` liga a subárvore inteira aninhada à esquerda e não um operando. O que
  continua a disparar, e são bugs: a cadeia que guarda **outra** chave, a
  disjunção **positiva-primeiro** (o deref corre exatamente quando o teste foi
  falso) e a guarda **negada** numa conjunção, em que a chave está provada
  ausente onde é lida;
- as quatro polaridades do ternário, com o deref no ramo guardado;
- um `return`/`throw`/`continue` antecipado sob `!containsKey` ou
  `get() == null`;
- a população por `put`, `putIfAbsent`, `computeIfAbsent` ou
  `if (!containsKey) { put(); }`;
- a **iteração sobre o próprio `keySet()`** —
  `for (String k : m.keySet()) { … m.get(k).trim() … }` — em que o cabeçalho
  do ciclo liga a chave a partir do próprio mapa, por isso a presença está
  garantida em todo o caminho que chega ao deref. É o idioma de iteração de
  mapas mais comum em Java e disparava. A exclusão exige que o mapa iterado
  seja o mapa dereferenciado **e** que a variável do ciclo seja a chave lida:
  iterar as chaves de um mapa e dereferenciar outro, ou dereferenciar uma
  chave diferente da do ciclo, continuam a disparar, e são bugs. Duas formas
  vizinhas continuam a disparar sobre código correto e são falsos positivos
  aceites: `for (Map.Entry<K,V> e : m.entrySet()) { … m.get(e.getKey()) … }`,
  em que a chave não é a variável do ciclo, e o keySet copiado para um local
  antes do ciclo, em que o cabeçalho já não menciona `keySet()`.

Cada uma está **limitada ao ramo que a guarda prova**, e essa limitação foi uma
regressão publicada antes de ser uma funcionalidade. Sem ela,
`pattern-not-inside: if (m.containsKey(k)) { … }` casa o **statement if-else
inteiro** e as cláusulas do ternário casavam a **expressão condicional
inteira** — os dois ramos ficavam excluídos, incluindo aquele em que o deref é
um NPE garantido:

```java
if (m.containsKey(k)) { return "present"; }
else { return m.get(k).trim(); }               // NPE certo; deixou de disparar
return m.containsKey(k) ? "present" : m.get(k).trim();   // idem
```

Medido num ficheiro com oito bugs desses: seis disparavam antes de as exclusões
de guarda entrarem, **um** depois, **oito** agora. Esse ficheiro é hoje uma
fixture (`hits/ElseArm.java`), a par de `hits/RealBugs.java`, e as duas contagens
são asseridas — é assim que a próxima exclusão tem de provar que não come um bug
real antes de entrar.

`X || m.containsKey(k)` continua a **não** ser tratado como guarda e continua a
disparar: `force` verdadeiro com a chave ausente é um NPE. É estruturalmente
distinto da forma negativa-primeiro, e é por isso que excluir uma não
reintroduz a outra.

A `modify-during-iteration` tinha um falso negativo que vale mais do que
qualquer dos seus falsos positivos. Um `remove()` dentro de um `switch`
seguido de `break;` é uma `ConcurrentModificationException` real — esse
`break` sai do *switch* e não do ciclo — e a exclusão emparelhada
`remove(); break;` engolia-a inteira:

```java
for (String s : items) {
    switch (s) {
        case "x": items.remove(s); break;   // CME real; não disparava
        default: break;
    }
}
```

A exclusão do `break` simples passou a aplicar-se só quando a remoção está
dentro de um `switch` que por sua vez está **dentro do for-each sobre essa
coleção**. É a **ordem do aninhamento** que a cláusula testa, e antes testava
mera contenção léxica: qualquer remoção dentro de um `case` reativava a regra,
incluindo uma dentro de um **ciclo** escrito nesse `case`, onde o `break`
simples sai do ciclo e o código está correto:

```java
switch (command) {
    case "purge":
        for (String s : items) {
            if (s.equals(target)) { items.remove(s); break; }  // correto
        }
        break;
}
```

`return`, `throw` e um `break` **etiquetado** saem mesmo do método ou do
ciclo a partir de dentro de um `switch`, por isso continuam excluídos em todo
o lado.

A `loop-lte-length` restringe a metavariável do array a um **tipo array**:
`$A.length` casava qualquer campo `int` chamado `length` e disparava em ERROR
sobre o ciclo deliberadamente inclusivo de um objeto de domínio. Medido, a
restrição não custa recall — parâmetro, local, campo, campo qualificado com
`this.` e local inferido com `var` continuam todos a ser vistos.

As exclusões terminadas em saída, nas três regras `map-get-deref`,
`optional-get-no-ispresent` e `modify-during-iteration`, toleram exatamente
**uma** instrução entre a guarda (ou a remoção) e a saída, em vez de uma
reticência arbitrária. Medido: a forma com reticências casa em PROFUNDIDADE,
por isso `if (!m.containsKey(k)) { if (strict) { return ""; } }` e
`items.remove(s); if (done) { break; }` deixavam os dois de disparar — e os
dois são bugs reais. O preço é a linha (5) da tabela de falsos positivos
aceites, mais abaixo.

A `empty-catch` respeita a convenção do Checkstyle / IntelliJ: nunca dispara se
a variável da exceção se chamar `ignore`, `ignored` ou `expected`. É a forma
auto-documentada de dizer "de propósito" sem um comentário de supressão — e o
reverso é que uma exceção genuinamente engolida escapa à regra só por ter esse
nome.

O segundo gume da mesma troca vale ser dito, porque a `empty-catch` é agora a
**única** regra em ERROR e todo o argumento dos tiers assenta nela: o idioma
JUnit de exceção esperada dispara em ERROR quando a variável apanhada se chama
`e`, e fica calada quando se chama `expected`. O idioma de teste tem de usar o
nome convencional.

```java
try { parse("nope"); throw new AssertionError("devia ter lançado"); }
catch (NumberFormatException e) { }          // dispara em ERROR
catch (NumberFormatException expected) { }   // calado
```

A `optional-get-no-ispresent` é **WARNING e não ERROR**, e isso aplica o
critério de tiers do pack em vez de o dobrar: ERROR é para o padrão que é bug
independentemente da intenção, e um `o.get()` só é bug quando está *sem
guarda*. A regra reconhece exatamente estas formas de guarda — enumeradas em
vez de resumidas, porque o resumo que aqui esteve ("inline sobre a mesma
variável `Optional`") era falsificável e foi falsificado por uma condição
composta, uma saída com mais do que uma instrução, um `while` e um
`Optional.of`:

- `if (o.isPresent())` sozinho **ou como qualquer dos operandos de uma
  conjunção** (`a.isPresent() && b.isPresent()`), **na condição de um `if`**,
  com o `get()` no ramo **verdadeiro**, com ou sem chavetas — o ramo `else` é
  um `NoSuchElementException` garantido e continua a disparar;
- `while (o.isPresent())`;
- o mesmo teste usado como **expressão** e não como condição de coisa nenhuma
  (`return o.isPresent() && o.get().isEmpty();`), mais as disjunções
  negativa-primeiro `!o.isPresent() || …` e `o.isEmpty() || …`, que fazem
  curto-circuito da mesma maneira;
- `return`/`throw`/`continue`/`break` antecipados sob `!isPresent()` ou
  `isEmpty()`, com ou sem **uma** instrução antes da saída;
- as três formas ternárias, com o `get()` no ramo que a condição prova seguro;
- `if (o.filter(p).isPresent())`;
- `Optional<T> o = Optional.of(…)`, que não pode estar vazio — `ofNullable`
  pode, e continua a disparar.

Falha **qualquer guarda que chegue ao teste através de outro método**, e
deliberadamente não trata `a.isPresent() || b` como guarda — isso não prova
nada sobre `a`, ao contrário da forma negativa-primeiro acima. O exemplo
concreto é a guarda delegada a um helper:

```java
if (!present(o)) { return "d"; }
return o.get();                    // dispara, e é código correto
```

Isso exige análise interprocedimental, que o Semgrep OSS não faz — a forma é
falso positivo e vai continuar a ser. Preferir WARNING a uma lista de exclusões
sem fim é a decisão que daí resulta, e essa decisão passou entretanto a
aplicar-se a todo o pack.

### Os tiers, e porque é que o teu fix PR de Java pode vir vazio

**Sete das oito regras estão em `WARNING`. Só a `empty-catch` está em `ERROR`.**

O critério é o do design (§4), aplicado a frio e enunciado como uma pergunta
sobre o *output* em vez de sobre o padrão:

> **Aquilo que a regra emite é sempre um bug?**

Não "a forma que ela procura costuma estar errada". Uma regra cuja correção
depende de ter reconhecido uma **guarda** emite um falso positivo sempre que
encontra uma forma de guarda que ninguém enumerou — e nenhuma lista de
exclusões fecha isso, porque a guarda pode estar sempre a um método de
distância, onde um matcher sintático não chega. Num motor sem dataflow quase
nada passa nesta barra: **uma em oito é o resultado honesto, não uma falha do
pack.**

A `empty-catch` passa por uma razão que vale a pena nomear, porque é a única
disponível: a sua válvula de escape **não é uma guarda**. É uma *declaração de
intenção que a própria regra lê* — a convenção `ignore` / `ignored` /
`expected` do Checkstyle / IntelliJ. Depois de a honrar, o que ela emite é um
engolir de exceção **não declarado**, e isso é bug independentemente do que o
autor tencionava.

A `loop-lte-length` desceu, mas só depois de o aperto óbvio ter sido **medido e
rejeitado**. Exigir que o corpo indexe mesmo o array (`<... $A[$I] ...>`)
corrige o ciclo que nunca indexa `a`, **não** corrige o ciclo-sentinela que
preenche um array maior (`b[i] = (i < a.length) ? a[i] : -1`, correto, e o
`a[i]` guardado está mesmo ali dentro do ternário), e **perde** um bug real em
que o índice fora dos limites é passado a um helper (`sum += at(a, i)`). Troca
um falso positivo por um falso negativo sem resolver o caso principal, por isso
os patterns ficaram como estavam e só o tier mudou.

**Consequência prática, e é a parte que morde.** O parser mapeia `ERROR` →
`high` e `WARNING` → `medium`. O `bug_hunt` **não filtra por omissão**, por
isso nada desaparece de um scan. Mas o `create_fix_pr` tem `severity_min` a
`high` por omissão — portanto, com sete das oito em `WARNING`, **o pack de Java
praticamente não contribui para o conjunto de fixes por omissão**. Se pediste
um fix PR de Java e veio vazio, é isto. Pede explicitamente:

```jsonc
{ "severity_min": "medium" }   // create_fix_pr, para apanhar o pack de Java
```

Essa omissão do `create_fix_pr` **não foi alterada**: afeta os quatro packs de
linguagem e é uma decisão à parte.

A `stream-not-closed` só reconhece `new FileInputStream(...)` — e só por esse
nome simples: um `new java.io.FileInputStream(...)` totalmente qualificado não
é visto (medido), tal como não são vistos `FileOutputStream`, `FileReader`,
`Socket` e os restantes closeables. É agora a única regra do pack com essa
lacuna: a `static-dateformat` traz um único padrão **totalmente qualificado**,
porque um campo `static final java.text.SimpleDateFormat` num ficheiro sem
import era invisível enquanto o padrão curto foi o único — e é exatamente
assim que se escreve a declaração quando não há import. Medido nas quatro
formas de import: o padrão qualificado casa também as formas curtas sempre que
um import deixa o Semgrep resolver o nome, o curto nunca casou a qualificada,
por isso o ramo curto era inerte e foi apagado.

Onze limitações são **aceites em vez de corrigidas**, cada uma reproduzida
contra as fixtures de revisão que existem hoje — a lista é exaustiva contra
essas, não contra todo o Java que existe.

**Cada linha diz a sua DIREÇÃO**, e isso não é formatação. Durante seis rondas
esta tabela teve nove linhas e as nove eram falsos positivos: ninguém estava a
olhar na direção do recall, por isso nunca lá se escreveu nada — e uma ronda
podia fechar um falso positivo, apagar recall em silêncio, e continuar verde.
As linhas 9 e 10 são as primeiras do outro lado. E uma linha SAIU da tabela na
ronda 8: a cadeia de conjunção nunca foi uma limitação, era só um `$X` que
ninguém tinha examinado.

| # | Dir | Regra | Código em que erra | Porque fica |
| --- | --- | --- | --- | --- |
| 1 | FP | `memory-leak-stream-not-closed` | `open(); try { … } finally { close(); }` | Já é a limitação declarada da regra, e já é a razão de ser `WARNING`. |
| 2 | FP | `race-condition-static-dateformat` | `static final SimpleDateFormat` cujos acessos passam todos por métodos `synchronized` | Provar que *todos* os acessos estão sincronizados é análise do programa inteiro, que o Semgrep OSS não faz. Aqui dizia-se também que "um formatter partilhado serializa todos os chamadores, por isso marcá-lo é defensável" — isso é um argumento de **produto**, não o critério do §4, e foi o que manteve a regra em `ERROR` durante quatro rondas a carregar um falso positivo documentado e não corrigível. O critério ganha: o finding fica, o tier passou a `WARNING`. |
| 3 | FP | `off-by-one-loop-lte-length` | `i <= a.length` com o corpo protegido por `i < a.length`, ou que nunca indexa `a` | O aperto óbvio foi **tentado e rejeitado** (medição acima): troca este falso positivo por um falso negativo num bug real sem resolver o caso principal. Os patterns ficaram; o tier desceu. |
| 4 | FP | `error-handling-printstacktrace-only` | `printStackTrace()` como fallback quando foi o próprio logger que lançou | O único sítio onde a chamada está certa; já é `WARNING`; estreito demais para codificar. |
| 5 | FP | `map-get-deref`, `optional-get-no-ispresent`, `modify-during-iteration` | **Duas ou mais** instruções entre a guarda (ou a remoção) e a saída: `if (!m.containsKey(k)) { log(); metric(); return ""; }`, `items.remove(s); log(s); n++; break;` | Preço deliberado. A alternativa — uma reticência de statement — casa em profundidade e engole `if (!m.containsKey(k)) { if (strict) { return ""; } }` e `items.remove(s); if (done) { break; }`, que são bugs reais. Um falso negativo que esconde um bug é pior do que este falso positivo. |
| 6 | FP | as mesmas três | Guarda delegada a um método helper: `if (!present(o)) { return d; }` | Exige análise interprocedimental, que o Semgrep OSS não faz. É a razão declarada de as três estarem em `WARNING` — e, generalizada, a razão de sete das oito regras do pack estarem lá. |
| 7 | FP | `map-get-deref` | Chave garantida fora das formas enumeradas: mapa preenchido num inicializador estático, ou mapeamento total sobre um enum declarado como `Map` | A garantia não está no caminho sintático que chega ao `get`. Excluir "qualquer mapa que alguma vez recebeu um `put`" apagaria a regra. |
| 8 | FP | `map-get-deref`, `optional-get-no-ispresent` | Guarda guardada num **booleano local**: `boolean present = m.containsKey(k); if (!present) { return ""; }` | É dataflow, não sintaxe. O Semgrep OSS não liga o valor do local ao teste que o produziu. |
| 9 | **FN** | `map-get-deref`, `optional-get-no-ispresent` | Garantia **invalidada** depois da guarda, dentro da região que a exclusão cobre: `if (m.containsKey(k)) { m.remove(k); return m.get(k).trim(); }`, `if (o.isPresent()) { o = Optional.empty(); return o.get(); }`, `m.put(k,"v"); m.remove(k); m.get(k).trim();`, `while (m.containsKey(k)) { m.remove(k); … }` | Cinco reproduções medidas, todas exceções garantidas, todas em silêncio. Mesma causa que o bug do ramo `else` — **o `pattern-not-inside` exclui o nó inteiro que casou** — mas no eixo **temporal** em vez do eixo dos ramos. A limitação ao ramo guardado corrigiu o eixo dos ramos; o eixo da sequência dentro desse ramo nunca foi examinado. Saber que `m.remove(k)` invalida `m.containsKey(k)` é dataflow, por isso é linha e não cláusula. A exclusão do `keySet()` herda-a. |
| 10 | **FN** | `map-get-deref`, `optional-get-no-ispresent` | Deref guardado por um **booleano local**: `boolean present = m.containsKey(k); if (present) { m.get(k).trim(); }` | O espelho da linha 8, que regista a mesma forma como falso positivo quando o booleano guarda uma saída antecipada. As duas direções são a mesma capacidade em falta (dataflow, não sintaxe), e ter só metade escrita durante seis rondas é a assimetria de que fala o preâmbulo. |
| 11 | FP | `map-get-deref` | As duas formas vizinhas do `keySet()` que a exclusão não alcança: `for (Map.Entry<K,V> e : m.entrySet()) { … m.get(e.getKey()) … }` e o keySet copiado para um local antes do ciclo | Na primeira a chave é `e.getKey()` e não a variável do ciclo; na segunda o cabeçalho já não menciona `keySet()`. A cláusula unifica o mapa **e** a chave de propósito, e alargá-la exige desistir de uma das unificações — os dois bugs reais que ficariam engolidos estão fixados como `b13` e `b14`. Das cinco formas corretas medidas, a cláusula fecha três. |

**Isto é só para JS/TS, Python, Go e Java.** Para as restantes linguagens desta secção —
C#, PHP, Ruby, Rust — a situação anterior mantém-se: o
pack que corre por default (`p/r2c-bug-scan`) só cobre estas classes para
Python e Go, os packs de linguagem opcionais (`p/javascript`, `p/typescript`,
etc., ligados via `include_language_packs`) são packs de segurança e não
acrescentam nenhuma, e nenhuma tem ainda um pack local próprio. O caminho
fiável para elas continua a ser o raciocínio guiado por modelo desta própria
skill — ficheiro a ficheiro pelas zonas críticas (secção 1) e os padrões e
fixes da secção 4 abaixo.

Mesmo em JS/TS, estas treze regras não substituem esse raciocínio: apanham
formas sintáticas, não motivos. Usa-as como primeira passada — não como
veredicto final. E lê a tabela de limitações aceites do pack JS/TS acima antes
de concluir que uma classe está coberta: `while`, comprimentos em cache,
`ngOnInit` e um cleanup que não limpa nada continuam a ser trabalho teu.

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
