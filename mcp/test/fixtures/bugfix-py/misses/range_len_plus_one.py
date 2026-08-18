def total(values):
    acc = 0
    for i in range(len(values)):
        acc += values[i]
    return acc


def last(values):
    return values[len(values) - 1]


def pairs(values):
    return [(i, values[i]) for i in range(len(values) - 1)]
