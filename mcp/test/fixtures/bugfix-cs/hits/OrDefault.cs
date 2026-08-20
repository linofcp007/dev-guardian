// HITS for bugfix-cs-null-safety-ordefault-deref: four sites, one per
// enumerated LINQ method plus a chained receiver.
//
// `FirstOrDefault()` and friends return `default(T)` on an empty sequence —
// null for a reference type. The whole reason to reach for the `OrDefault`
// variant instead of `First()` is that the sequence MIGHT be empty, so
// dereferencing the result immediately contradicts the choice of method.
using System.Collections.Generic;
using System.Linq;

namespace Guardian.Fixtures.Hits;

public sealed class Customer
{
    public string Name { get; init; } = "";

    public int Id { get; init; }
}

public sealed class OrDefault
{
    // 1.
    public string FirstThenDeref(List<Customer> customers)
    {
        return customers.FirstOrDefault().Name;
    }

    // 2.
    public string SingleThenDeref(List<Customer> customers)
    {
        return customers.SingleOrDefault().Name;
    }

    // 3.
    public string LastThenDeref(List<Customer> customers)
    {
        return customers.LastOrDefault().Name;
    }

    // 4. A CHAINED receiver. `$X` binds the whole `customers.Where(...)`
    //    subtree, which is what makes the rule work on the spelling people
    //    actually write — a filter followed by a first-or-default.
    public string FilteredThenDeref(List<Customer> customers)
    {
        return customers.Where(c => c.Id > 1).FirstOrDefault().Name;
    }
}
