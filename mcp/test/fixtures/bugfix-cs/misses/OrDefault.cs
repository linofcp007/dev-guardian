// NEAR-MISSES for bugfix-cs-null-safety-ordefault-deref.
//
// This rule carries NO exclusion clauses at all, and that is a deliberate
// result rather than an omission: the correct shapes are silent because they
// are different AST nodes, not because anything was written to exclude them.
// So every method here is FREE — delete the whole rule body except the three
// positive patterns and this file still passes.
//
// It is kept because it is a regression net, not evidence of precision. The
// day someone adds a via-a-local branch — `var c = xs.FirstOrDefault(); c.Name`
// — these shapes stop being free and this file starts earning its place.
// Measured while probing that branch: it fires on the guarded forms below, so
// it would need a full guard battery before it could ship — and the pack's one
// attempt at such a battery, `as-cast-deref`, was deleted for being wrong 6490
// times on real C# with every fixture green. Read that as the cost of the
// branch, not as a reason to skip the battery.
using System;
using System.Collections.Generic;
using System.Linq;

namespace Guardian.Fixtures.Misses;

public sealed class Customer
{
    public string Name { get; init; } = "";

    public int Id { get; init; }
}

public sealed class OrDefault
{
    // Null-conditional: a different node from `.`.
    public string NullConditional(List<Customer> customers)
    {
        return customers.FirstOrDefault()?.Name ?? "";
    }

    // Coalesced to a non-null fallback before the dereference.
    public string Coalesced(List<Customer> customers)
    {
        return (customers.FirstOrDefault() ?? new Customer()).Name;
    }

    // `First()` throws on empty instead of returning null. Dereferencing it is
    // correct — the exception is the contract.
    public string FirstThrows(List<Customer> customers)
    {
        return customers.First().Name;
    }

    // Stored and guarded.
    public string StoredAndGuarded(List<Customer> customers)
    {
        var c = customers.FirstOrDefault();
        if (c != null) { return c.Name; }
        return "";
    }

    // Stored with an early exit.
    public string StoredWithEarlyReturn(List<Customer> customers)
    {
        var c = customers.FirstOrDefault();
        if (c == null) { return ""; }
        return c.Name;
    }

    // `DefaultIfEmpty` + `First` is the explicit-fallback spelling.
    public string DefaultIfEmpty(List<Customer> customers)
    {
        return customers.DefaultIfEmpty(new Customer()).First().Name;
    }
}
