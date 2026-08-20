// POSITIVE CONTROL for the no-duplication proof — the C# half.
//
// The proof is "the registry packs find NOTHING in our hit fixtures, so every
// local rule is additive". That is worthless on its own if a pack never ran
// for this language: a pack with no C# rules looks byte-identical to a clean
// result. This file makes the zero mean something, by being code a registry
// pack DOES fire on.
//
// `DES.Create()` trips `use_deprecated_cipher_algorithm` in `p/csharp`.
// Measured, and chosen over the concatenated-SQL shape the design named for
// two reasons: `csharp-sqli` needs `System.Data.SqlClient`, a package these
// fixtures deliberately do not carry, so that version could not COMPILE; and
// this one does, which keeps the control inside the same "every fixture
// builds" gate as everything else.
//
// WHAT THIS FILE CANNOT DO, stated because the gap is real. It is a control
// for `p/csharp` only. See control_r2c.py for `p/r2c-bug-scan`, and see the
// test file for `p/security-audit`, for which NO positive control was found —
// measured against eleven classic vulnerable C# shapes across two batteries
// (concatenated SQL, MD5, SHA1, DES, command injection, hardcoded password,
// insecure Random, disabled TLS validation, XXE, path traversal,
// BinaryFormatter) and it fired on none of them.
//
// DO NOT "FIX" THIS CODE. It is deliberately weak crypto and is never
// executed; making it safe silently disables the control and the
// no-duplication test starts passing for the wrong reason. The Go round lost a
// control directory exactly this way — nothing enumerated it, it was deleted,
// and the test went on passing while merely SKIPPING.
using System.Security.Cryptography;

namespace Guardian.Fixtures.Control;

public sealed class Control
{
    public static SymmetricAlgorithm DeprecatedCipher()
    {
        return DES.Create();
    }
}
