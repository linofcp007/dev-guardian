# POSITIVE CONTROL FOR p/r2c-bug-scan, AND IT IS PYTHON ON PURPOSE.
#
# That pack ships NO PHP RULES AT ALL: pointed at the PHP fixtures it reports
# `paths.scanned = 0`, so a zero finding count there is not evidence of
# anything -- not "we are additive", just "it never ran". No PHP control could
# rescue it either, because there is no PHP rule for a PHP control to trip.
#
# The only way to distinguish the two is to prove the pack is alive in a
# language it does cover, which is what this file is for. `a == a` is
# `python.lang.correctness.useless-eqeq`.
def f(a):
    if a == a:
        return 1
    return 0
