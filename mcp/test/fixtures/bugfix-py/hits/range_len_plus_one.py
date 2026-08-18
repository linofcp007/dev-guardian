def total(values):
    acc = 0
    for i in range(len(values) + 1):
        acc += values[i]
    return acc


def last(values):
    return values[len(values)]
