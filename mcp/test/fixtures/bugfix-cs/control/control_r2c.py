# POSITIVE CONTROL for the no-duplication proof — the p/r2c-bug-scan half.
#
# THIS FILE IS PYTHON ON PURPOSE, IN A C# FIXTURE TREE, and that is the single
# most important thing to know before touching it.
#
# `p/r2c-bug-scan` ships NO C# RULES AT ALL. Measured: pointed at the eleven C#
# hit fixtures it reports `paths.scanned = 0`, `results = 0`, `errors = 0`. So
# "the bug pack finds nothing in our fixtures" is not evidence of anything for
# this language — the pack never looked. A C# control cannot rescue it either,
# because there is no C# rule for a C# control to trip.
#
# The only way to distinguish "additive" from "never ran" is to prove the pack
# is ALIVE at all, in a language it does cover. `useless-eqeq` is one of its
# own rules, and comparing a variable to itself is the shape it looks for.
#
# DO NOT "FIX" THIS CODE, and do not move it out for being the wrong language.
# It is never imported and never executed.


def useless_comparison(value):
    # `x == x` is always True — p/r2c-bug-scan's `useless-eqeq`.
    if value == value:
        return "always"
    return "never"
