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
