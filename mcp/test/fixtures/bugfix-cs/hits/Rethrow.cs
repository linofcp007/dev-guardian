// HITS for bugfix-cs-error-handling-rethrow-loses-stacktrace: nine sites,
// every one a real defect. `throw ex;` inside a `catch (E ex)` resets
// Exception.StackTrace to the rethrow point, so the frame that actually threw
// is gone by the time anything logs it.
//
// This file has an INDEPENDENT ORACLE, which no other fixture in the series
// has had: `dotnet build` emits CA2200 ("Rethrow to preserve stack details")
// and it must fire at exactly these nine sites and nowhere else. The
// hit/miss split is therefore not graded by the rule's own author.
//
// It earned its keep on the ninth site. The rule missed a `throw ex;` whose
// catch had a `finally` after it; CA2200 did not, and the disagreement is the
// only reason the gap was found before it shipped.
//
// ---------------------------------------------------------------------------
// HOW TO BUILD THESE FIXTURES. The project file is deliberately NOT committed,
// matching the Go and Java rounds — a build file inside the fixture tree is a
// file every `paths.scanned` assertion would have to account for. So the
// recipe lives here rather than only in a report, because two of these
// properties are load-bearing and the third saves an afternoon:
//
//   <TargetFramework>net8.0</TargetFramework>
//   <Nullable>enable</Nullable>                     REQUIRED: misses/Rethrow.cs
//                                                   uses `Exception? pending`,
//                                                   and without it you get a
//                                                   CS8632 you will not expect
//   <ImplicitUsings>disable</ImplicitUsings>
//   <EnableNETAnalyzers>true</EnableNETAnalyzers>   CA2200 comes from here
//   <AnalysisLevel>latest</AnalysisLevel>
//
// Put all four .cs files in ONE project — the namespaces keep hits/ and
// misses/ from colliding — and run:
//
//   docker run --rm -v "<abs>:/w" -w //w mcr.microsoft.com/dotnet/sdk:8.0 \
//       dotnet build --no-incremental
//
// `--no-incremental` matters: a second `dotnet build` reports 0 warnings
// because it does not recompile, and the CA2200 evidence silently vanishes.
// Expected: `0 Error(s)` and 17 warnings — 9 CA2200 plus 8 CS0168 on the
// deliberately unused catch variables in the two EmptyCatch.cs files.
// ---------------------------------------------------------------------------
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

    // 9. In a catch with a trailing `finally` — the shape that was invisible
    //    when this pack first shipped, and the reason this fixture now has
    //    nine sites instead of eight.
    //
    //    A try statement WITH a finalizer is a DIFFERENT AST node, so
    //    `try { ... } catch (...) { ... }` does not match it at all. The
    //    stack trace is reset exactly as it is in `Simple` eight methods up;
    //    the `finally` has nothing to do with the defect. Measured both
    //    ways: the plain `pattern-inside` matches only the no-finally form,
    //    the `finally` one matches only this form, and the two are DISJOINT
    //    — which is why the rule enumerates both rather than widening one.
    //
    //    The oracle agrees: CA2200 fires here too, and it was CA2200 that
    //    proved this was a false negative rather than a deliberate omission.
    public void WithFinally(string p)
    {
        try { Parse(p); }
        catch (FormatException ex) { throw ex; }
        finally { Cleanup(); }
    }

    private static void Parse(string p) => int.Parse(p);

    private static void Log(Exception ex) => Console.Error.WriteLine(ex.Message);

    private static void Cleanup() { }
}
