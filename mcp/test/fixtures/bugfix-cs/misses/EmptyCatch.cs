// NEAR-MISSES for bugfix-cs-error-handling-empty-catch.
//
// Written BEFORE hits/EmptyCatch.cs. If any method here fires, the rule is
// wrong.
//
// The three naming exemptions are the rule's only escape hatch, and it is not
// a guard: it is a DECLARATION OF INTENT the rule itself reads. Semgrep
// matches the AST and comments are not in it, so a catch documented as a
// deliberate ignore is byte-identical to a silent swallow — the comment could
// never be the hatch. The name can be, and it is already the convention of
// the standard linters: Checkstyle's `ignore`/`expected`, IntelliJ's
// `ignored`. Roslyn has no equivalent default, so the vocabulary is inherited
// from the Java pack rather than from a C# tool.
using System;

namespace Guardian.Fixtures.Misses;

public sealed class EmptyCatch
{
    // The failure is recorded.
    public void Logs(string p)
    {
        try { Parse(p); } catch (FormatException ex) { Log(ex); }
    }

    // The failure is rethrown wrapped.
    public void Rethrows(string p)
    {
        try { Parse(p); } catch (FormatException ex) { throw new InvalidOperationException("bad input", ex); }
    }

    // The three naming conventions, one method each, and each is
    // DISCRIMINATING for one alternative of the `metavariable-regex`: drop
    // `ignored` from it and only IgnoredName fires, and so on.
    public void IgnoredName(string p)
    {
        // IntelliJ's convention. A non-numeric string is expected here.
        try { Parse(p); } catch (FormatException ignored) { }
    }

    public void IgnoreName(string p)
    {
        // Checkstyle's first default.
        try { Parse(p); } catch (FormatException ignore) { }
    }

    public void ExpectedName(string p)
    {
        // Checkstyle's second default: the throw IS the assertion.
        try { Parse(p); } catch (FormatException expected) { }
    }

    // An exception FILTER whose body logs. The filter is the shape most
    // likely to confuse a `catch ($E $V) { }` pattern, because the `when`
    // clause sits between the parameter and the block.
    public void FilteredAndLogged(string p)
    {
        try { Parse(p); } catch (FormatException ex) when (p.Length > 0) { Log(ex); }
    }

    // try/finally with NO catch clause at all. Nothing is swallowed — the
    // exception propagates.
    public void FinallyOnly(string p)
    {
        try { Parse(p); } finally { Cleanup(); }
    }

    // The same, with an EMPTY finally block. This is the near-miss for the
    // bare `catch { }` branch specifically: the token before the empty block
    // is the only thing distinguishing the two, so a branch written as
    // `try { ... } { }` — or one that matched any trailing empty block —
    // would fire here.
    public void EmptyFinallyBlock(string p)
    {
        try { Parse(p); } finally { }
    }

    private static void Parse(string p) => int.Parse(p);

    private static void Log(Exception ex) => Console.Error.WriteLine(ex.Message);

    private static void Cleanup() { }
}
