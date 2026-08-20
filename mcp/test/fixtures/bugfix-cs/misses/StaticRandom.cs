// NEAR-MISSES for bugfix-cs-race-condition-static-random. Written first.
//
// `Random` is not thread-safe. A `static Random` shared across threads has its
// internal state corrupted by concurrent `Next()` calls, and the classic
// symptom is not a crash but a long run of identical or zero values — a bug
// that survives review because the code looks obviously fine.
using System;

namespace Guardian.Fixtures.Misses;

public sealed class StaticRandom
{
    // `Random.Shared` is the .NET 6+ answer, and it IS thread-safe. A static
    // field holding it is correct, and it is the near-miss for the
    // `new Random(...)` half of the pattern specifically: the field is static,
    // the type is Random, and only the initialiser tells the two apart.
    private static readonly Random Shared = Random.Shared;

    // An INSTANCE field. Not shared across threads by construction, so the
    // near-miss for the `static` half of the pattern.
    private readonly Random _instance = new Random();

    // A local. Same reasoning, and the commonest correct spelling.
    public int RollLocally()
    {
        var rng = new Random();
        return rng.Next(1, 7);
    }

    public int RollShared() => Shared.Next(1, 7);

    public int RollInstance() => _instance.Next(1, 7);

    // Using Random.Shared directly, with no field at all.
    public int RollDirect() => Random.Shared.Next(1, 7);
}
