import contextlib


def managed(path, rows):
    with open(path, "w") as handle:
        for row in rows:
            handle.write(row)


def explicit(path, rows):
    handle = open(path, "w")
    try:
        for row in rows:
            handle.write(row)
    finally:
        handle.close()


class Writer:
    def __init__(self, path):
        self.handle = open(path, "w")

    def close(self):
        self.handle.close()


# --- Written by the AUDITOR. Every function below is OWNERSHIP TRANSFER: the
# --- handle leaves this scope and something else closes it, so closing here
# --- would be the bug. Five of the six fired. Each is DISCRIMINATING against
# --- its own exclusion clause.


# The handle is RETURNED from a factory.
def opener(path):
    handle = open(path, "w")
    return handle


# Registered with an ExitStack, which closes it.
def via_exit_stack(paths):
    with contextlib.ExitStack() as stack:
        for p in paths:
            handle = open(p)
            stack.enter_context(handle)
        return stack


# Closed via contextlib.closing.
def via_closing(path):
    handle = open(path)
    with contextlib.closing(handle) as h:
        return h.read()


# Yielded from a generator-based context manager; the caller's `with` closes
# it in the finally.
@contextlib.contextmanager
def yielded(path):
    handle = open(path)
    try:
        yield handle
    finally:
        handle.close()


# Stored into a dict of handles that is returned and closed elsewhere.
def pool(paths):
    handles = {}
    for p in paths:
        handle = open(p)
        handles[p] = handle
    return handles


def pool_list(paths):
    handles = []
    for p in paths:
        handle = open(p)
        handles.append(handle)
    return handles


# A module-level log handle, closed by atexit or by the process ending. There
# is no close() in the same scope because there is no scope, and that is why
# the rule is now anchored inside a `def`. DISCRIMINATING: delete the
# `pattern-inside: def` clause and this fires.
LOGFILE = open("/tmp/app.log", "a")


# A plain generator that hands the handle to whoever consumes it — the same
# ownership transfer as `return handle`, with no close in this scope at all.
# It is the near-miss for the `yield $F` clause specifically: the
# `@contextmanager` version above closes in a `finally`, so the close clause
# covers it and the yield clause was dead behind it (measured).
def open_and_yield(path):
    handle = open(path)
    yield handle
