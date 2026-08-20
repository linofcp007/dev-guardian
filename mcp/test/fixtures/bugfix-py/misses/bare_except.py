def load(path):
    try:
        return read_file(path)
    except OSError as exc:
        log(exc)
        raise


# --- Written by the AUDITOR. Cleanup-then-reraise is the dominant legitimate
# --- use of a bare `except:`: nothing is swallowed, and the bare form is
# --- deliberate precisely because the cleanup has to run for EVERY exception.
# --- The shipped rule fired on 3 of the 4 functions in the auditor's probe,
# --- all three of them this shape. DISCRIMINATING: delete the `raise`
# --- exclusion and all three fire.
def rollback_and_reraise(conn):
    try:
        conn.execute("...")
    except:
        conn.rollback()
        raise


def worker_loop(job):
    try:
        job.run()
    except:
        log_exception()
        raise


# The same, with a `finally` — which is also the shape that used to silence
# the rule outright, so this one is doing two jobs at once.
def shutdown(res):
    try:
        res.use()
    except:
        res.release()
        raise
    finally:
        res.mark()


# The same cleanup-then-reraise with an `else` arm. The re-raise exclusion is
# written once per try-shape, and without a near-miss per shape the `else`
# clause is dead.
def reraise_with_else(res):
    try:
        v = res.use()
    except:
        res.release()
        raise
    else:
        return v
