def a(conn):
    try:
        conn.commit()
    except ValueError as exc:
        log(exc)


def b(conn):
    try:
        conn.commit()
    except ValueError:
        raise


def c(conn):
    try:
        conn.commit()
    except ValueError:
        pass
        log("recovered")


# --- Written by the AUDITOR. `try: import x / except ImportError: pass` is
# --- the optional-dependency probe, and it is the ONE exception type whose
# --- `pass` handler has no other reading — every library with an optional
# --- dep has this. DISCRIMINATING: delete the ImportError exclusion and all
# --- three fire.
try:
    import orjson
except ImportError:
    pass

try:
    import uvloop
except ModuleNotFoundError:
    pass


def optional_backend():
    try:
        import ujson
    except ImportError:
        pass


# The modern spelling of a deliberate swallow, and what this rule's message
# now recommends writing instead. It is not a `try` at all, so it never
# matched — recorded here so the recommendation and the rule agree.
def suppressed(tmp):
    import contextlib
    import os

    with contextlib.suppress(FileNotFoundError):
        os.remove(tmp)


# The optional-dependency probe with a `finally` and with an `else`. The
# ImportError carve-out is written once per try-shape, and without a
# near-miss per shape two of the three clauses are dead.
def optional_with_finally():
    try:
        import ujson
    except ImportError:
        pass
    finally:
        mark_probe_done()


def optional_with_else():
    try:
        import ujson
    except ImportError:
        pass
    else:
        register(ujson)
