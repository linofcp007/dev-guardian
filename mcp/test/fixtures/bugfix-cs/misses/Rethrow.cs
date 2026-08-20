// NEAR-MISSES for bugfix-cs-error-handling-rethrow-loses-stacktrace.
//
// Written BEFORE hits/Rethrow.cs, per the design's third governing rule: the
// correct C# that most resembles the bug comes first, so the rule is graded
// against it rather than fitted to the bug fixture afterwards.
//
// If ANY method here fires, the rule is wrong. `dotnet build` is the
// independent oracle for this pair: it must emit CA2200 ("Rethrow to preserve
// stack details") at zero sites in this file.
using System;

namespace Guardian.Fixtures.Misses;

public sealed class AppEx : Exception
{
    public AppEx(string message, Exception inner) : base(message, inner) { }
}

public sealed class Rethrow
{
    // 1. THE correct form, and the reason this rule can sit at ERROR: `throw;`
    //    is a DIFFERENT AST node from `throw ex;`, not a guarded version of
    //    it. There is nothing here for a syntactic matcher to mistake.
    public void BareRethrow(string p)
    {
        try { Parse(p); }
        catch (FormatException ex) { Log(ex); throw; }
    }

    // 2. Wrapping. The caught exception becomes InnerException, so the
    //    original stack trace survives inside the new one.
    public void WrapInNew(string p)
    {
        try { Parse(p); }
        catch (FormatException ex) { throw new AppEx("parse failed", ex); }
    }

    // 3. `throw ae.Flatten()` — a NEW exception derived from the caught one.
    //    The closest shape to `throw ae;` that is not it: same receiver, same
    //    statement, one member access apart. The rule unifies $V with the
    //    catch identifier and matches a bare identifier, so a call on it is
    //    not a match.
    public void FlattenAggregate(Action work)
    {
        try { work(); }
        catch (AggregateException ae) { throw ae.Flatten(); }
    }

    // 4. The same idea moved into a helper, so the wrapping is invisible at
    //    the throw site. `throw Wrap(ex);` is still not `throw ex;`.
    public void WrapViaHelper(string p)
    {
        try { Parse(p); }
        catch (FormatException ex) { throw Wrap(ex); }
    }

    // 5. Captured in the catch and thrown OUTSIDE it. This is the near-miss
    //    for the `pattern-inside` clause specifically: `throw pending;` IS a
    //    bare-identifier throw, and the only thing keeping the rule off it is
    //    that it does not sit inside a catch block. Delete the
    //    `pattern-inside` and this method starts firing — which is what makes
    //    it discriminating rather than decorative.
    public void ThrowOutsideCatch(string p)
    {
        Exception? pending = null;
        try { Parse(p); }
        catch (FormatException ex) { pending = ex; }
        if (pending is not null) { throw pending; }
    }

    private static AppEx Wrap(Exception ex) => new AppEx("wrapped", ex);

    private static void Parse(string p) => int.Parse(p);

    private static void Log(Exception ex) => Console.Error.WriteLine(ex.Message);
}
