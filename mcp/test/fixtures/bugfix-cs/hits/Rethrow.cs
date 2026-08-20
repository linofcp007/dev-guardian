// HITS for bugfix-cs-error-handling-rethrow-loses-stacktrace: eight sites,
// every one a real defect. `throw ex;` inside a `catch (E ex)` resets
// Exception.StackTrace to the rethrow point, so the frame that actually threw
// is gone by the time anything logs it.
//
// This file has an INDEPENDENT ORACLE, which no other fixture in the series
// has had: `dotnet build` emits CA2200 ("Rethrow to preserve stack details")
// and it must fire at exactly these eight sites and nowhere else. The
// hit/miss split is therefore not graded by the rule's own author.
using System;
using System.IO;

namespace Guardian.Fixtures.Hits;

public sealed class Rethrow
{
    // 1. The minimal shape.
    public void Simple(string p)
    {
        try { Parse(p); }
        catch (FormatException ex) { throw ex; }
    }

    // 2. Nested inside an `if`. The rethrow is no longer the catch body, so a
    //    rule written as `catch ($E $V) { throw $V; }` would miss it — the
    //    `pattern-inside` form is what keeps this one visible.
    public void InsideIf(string p, bool fatal)
    {
        try { Parse(p); }
        catch (FormatException ex)
        {
            if (fatal) { throw ex; }
            Log(ex);
        }
    }

    // 3. Inside a `for` in the catch body.
    public void InsideLoop(string p, int attempts)
    {
        try { Parse(p); }
        catch (FormatException ex)
        {
            for (var i = 0; i < attempts; i++)
            {
                if (i > 3) { throw ex; }
            }
            Log(ex);
        }
    }

    // 4. Under an exception FILTER. The `when` clause sits between the
    //    parameter and the block, which is exactly where a pattern written
    //    against the unfiltered shape stops matching.
    public void UnderFilter(string path)
    {
        try { File.ReadAllText(path); }
        catch (IOException ex) when (ex.Message.Length > 0) { throw ex; }
    }

    // 5. The first of TWO catch clauses, with the second doing it correctly on
    //    the next line. This is where the $V unification earns its place: the
    //    rule must fire on the `throw ex;` and stay silent on the `throw;`
    //    one line below, in the same statement.
    public void FirstOfTwo(string p)
    {
        try { Parse(p); }
        catch (FormatException ex) { throw ex; }
        catch (OverflowException) { throw; }
    }

    // 6. After a logging statement, which is the commonest real spelling: the
    //    author meant "log and rethrow" and lost the stack trace doing it.
    public void AfterLogging(string p)
    {
        try { Parse(p); }
        catch (FormatException ex) { Log(ex); throw ex; }
    }

    // 7. After a `using` block inside the catch.
    public void AfterUsingBlock(string p, string logPath)
    {
        try { Parse(p); }
        catch (FormatException ex)
        {
            using (var w = new StreamWriter(logPath, true)) { w.WriteLine(ex.Message); }
            throw ex;
        }
    }

    // 8. Inside a `switch` arm in the catch body.
    public void InsideSwitch(string p, int mode)
    {
        try { Parse(p); }
        catch (FormatException ex)
        {
            switch (mode)
            {
                case 0: throw ex;
                default: Log(ex); break;
            }
        }
    }

    private static void Parse(string p) => int.Parse(p);

    private static void Log(Exception ex) => Console.Error.WriteLine(ex.Message);
}
