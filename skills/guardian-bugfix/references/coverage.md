# Bug-pack coverage — what each rule misses

Read this before telling the user a bug class is covered. The packs are `configs/semgrep/bugfix-<lang>.yml`
in the plugin; their comments and the CHANGELOG hold the measurements behind every line below. FN = a real bug
the rule stays silent on; FP = correct code it flags.

**Tiers.** A rule is `ERROR` (`high`) only when everything it emits is a bug. A rule whose answer depends on
recognising a guard is `WARNING` (`medium`): a guard it never enumerated — one call away, or in a local boolean
— turns into a false positive, and no exclusion list closes that without dataflow. `create_fix_pr` applies none
of these rules at any `severity_min` (none ships a `fix:`): use `suggest_fix` and write the patch.

## JS / TS — 13 rules (`index-at-length` ERROR, `parseint-without-radix` INFO, the rest WARNING)

- `empty-catch`, `empty-promise-catch` — FP: a deliberate fail-open explained by a comment (Semgrep reads no
  comments). A binding named `ignore`, `ignored`, `expected` or starting with `_` is honoured; otherwise
  `// nosemgrep` with a reason.
- `unchecked-find` — needs a literal callback (that is what tells `Array#find` from a Mongoose query); FN: a
  named predicate, `users.find(byId).name`.
- `floating-mutation` — the receiver must look like persistence (`repo.save`); excludes `void`,
  `Promise.all`, `.then/.catch/.finally` and a captured promise. FN: a repository variable without such a
  name; async function expressions.
- `loop-lte-length` — matches the out-of-range read. FN: `while` / `do-while`, `i < a.length + 1`, a cached
  length (`const n = a.length`, common in hot paths), `s.charAt(i)`.
- `unchecked-match` — FP: a `match` method on another object (`matcher.match(url)[0]`); FP for it,
  `unchecked-find` and `reduce-without-initial`: a guard earlier in the function.
- `listener-without-cleanup`, `subscribe-without-unsubscribe` — anchored on `useEffect`. FN: other lifecycles
  (`componentDidMount`, `ngOnInit`, `onMounted`, `useLayoutEffect`), `emitter.on(...)`, a cleanup that removes
  nothing, a second registration beside a cleaned one.
- `interval-without-clear` — FN: a cleanup registered through a callback (`registry.add(() => clearInterval(t))`).

## Python — 10 rules (`none-deref-match` ERROR)

- No rule for a forgotten `await` on the project's own `async def` — only named `asyncio` primitives.
- `queryset-n-plus-one` — FN: the queryset bound to a variable before the loop, a related field reached
  through a method.
- `none-deref-dict-get` — needs a literal key; FN: `cfg.get(key).strip()`.
- `none-deref-match` — module form only; FN: a compiled pattern, `PAT.match(t).group(1)`.
- `open-without-context` — FN: `self.handle = open(path)` and any handle that escapes the scope.
- `toctou-exists-open` — read modes only.

## Go — 9 rules (`empty-err-block` ERROR)

- No rule for hung goroutines or loop-variable capture (Go 1.22 changed its semantics, and Semgrep cannot read
  `go.mod`). For `xs = append(xs, v)` on a parameter, `staticcheck` / `ineffassign`.
- `nil-map-write` — FN: a nil map received as a parameter or returned by a constructor.
- `type-assert-no-ok` — FP: `var s, ok = v.(string)`.
- `err-discarded` — FP: the project's own `(T, bool)` functions (only a short standard-library deny-list).

## Java — 7 rules, all WARNING

- No rule for `Integer ==` (needs type inference).
- `modify-during-iteration` — exact declared types only (`List`, `ArrayList`, `LinkedList`, `Set`, `HashSet`,
  `LinkedHashSet`, `Collection`); FN: `Deque`, `Queue`, `SortedSet`, custom collections.
- `stream-not-closed` — only `new FileInputStream(...)`, short name; FP: `open(); try { … } finally { close(); }`.
- `static-dateformat` — FP: every access already `synchronized`.
- `loop-lte-length` — FP: a loop that never indexes the array, or fills a larger one.
- `optional-get-no-ispresent` — FP: a guard in a helper method or a local boolean, two or more statements
  between the guard and the exit; FN: the guarantee invalidated after the guard (`o = Optional.empty()`).
- `empty-catch` — FP: intent stated in a comment (most real empty catches).

## C# — 11 rules (`rethrow-loses-stacktrace` ERROR)

- No `IDisposable` rule: Semgrep drops the `using` modifier, so the recommended form would look like a leak.
- `blocking-on-task` — FN: `var t = GetAsync(); t.Result`, `Task.Run(...).Result`, a dotted receiver's
  `.Wait()`.
- `ordefault-deref` — FP: a value-type sequence (`List<int>.FirstOrDefault().ToString()`).
- `loop-lte-length` — FP: a loop filling `new int[a.Length + 1]`.
- `modify-during-iteration` — `Dictionary` is excluded (removal is safe since .NET Core 3.0).
- Write `var` in a C# pattern: `$T $V = ...` only matches explicitly typed declarations.

## PHP — 6 rules, all WARNING

- No resource-leak rule (it needs escape analysis).
- `empty-catch` — FP: a deliberate silence explained by a comment; FN: PHP 8's `catch (\Foo) { }` without a
  variable.

## Rust — 1 rule, WARNING

`blocking-sleep-in-async`: `std::thread::sleep` in an `async fn`. Excludes `spawn_blocking`, `thread::spawn`
and their closures; FP: an application helper of another name that moves the work off the executor; FN:
an `async` block inside a synchronous `fn` (`tokio::spawn(async move { thread::sleep(d); })` in `main`).
For more coverage, configure `cargo clippy` (`-W clippy::pedantic`, the `restriction` lints) instead of
adding rules.

## Ruby — none

Semgrep's Ruby frontend erases `&.` and the `..` / `...` distinction, so nil-safety and off-by-one rules would
match the correct and the buggy form alike. Recommend RuboCop and the `p/ruby` registry pack.
