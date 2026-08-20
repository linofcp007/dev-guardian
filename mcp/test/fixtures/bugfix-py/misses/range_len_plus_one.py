def total(values):
    acc = 0
    for i in range(len(values)):
        acc += values[i]
    return acc


def last(values):
    return values[len(values) - 1]


def pairs(values):
    return [(i, values[i]) for i in range(len(values) - 1)]


def dp_seed(a):
    n = len(a)
    dp = [0] * (n + 1)
    for i in range(len(a) + 1):
        dp[i] = i
    return dp


# --- Written by the AUDITOR. `d[len(d)] = v` is an ASSIGNMENT to a fresh key
# --- — indexing a dict by its own current size, the standard insertion-order
# --- and vocabulary-builder idiom — not an out-of-bounds read. Two of the
# --- four hits in the auditor's probe were this. DISCRIMINATING: delete the
# --- assignment-target exclusion and both fire.
def index_by_insertion_order(items):
    d = {}
    for it in items:
        d[len(d)] = it
    return d


def registry(names):
    import collections

    reg = collections.OrderedDict()
    for n in names:
        reg[len(reg)] = n
    return reg


# Slice assignment at the end, equivalent to .extend(). A Slice is a
# different AST node from a Subscript, so this is DOCUMENTARY.
def append_via_slice(xs, ys):
    xs[len(xs):] = ys
    return xs


# The n+1 loop that reads the ORIGINAL array only at i-1. Correct, and
# DISCRIMINATING for the body requirement: drop `<... $X[$I] ...>` and it
# fires, because `ps[i]` is not `a[i]`.
def prefix_sums(a):
    ps = [0] * (len(a) + 1)
    for i in range(len(a) + 1):
        if i > 0:
            ps[i] = ps[i - 1] + a[i - 1]
    return ps
