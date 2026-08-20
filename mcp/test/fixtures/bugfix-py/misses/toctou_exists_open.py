import os


def read_guarded(path):
    try:
        return open(path).read()
    except FileNotFoundError:
        return ""


def check_only(path):
    if os.path.exists(path):
        return True
    return False


def open_after_block(path):
    if os.path.exists(path):
        log("found")
    return open(path).read()


def open_in_else(path):
    if os.path.exists(path):
        return ""
    else:
        return open(path).read()


def open_other_path(a, b):
    if os.path.exists(a):
        return open(b).read()
    return ""


# --- Written by the AUDITOR. Testing for existence before WRITING is the
# --- opposite direction: the check protects against clobbering, not against
# --- a missing file, and the rule's advice ("open directly and catch
# --- FileNotFoundError") does not apply. Both fired.
# --- DISCRIMINATING: delete the write-mode exclusions and write_backup fires.
def write_backup(path):
    if os.path.exists(path):
        os.rename(path, path + ".bak")
        open(path, "w").write("")


def ensure(path):
    if os.path.exists(path):
        log("exists")
    else:
        open(path, "w").close()


def append_log(path, line):
    if os.path.exists(path):
        open(path, "a").write(line)


# The remaining write modes. One near-miss per excluded mode, because a
# `pattern-not` nothing exercises can be deleted while the suite stays green.
def write_binary_backup(path):
    if os.path.exists(path):
        open(path, "wb").write(b"")


def append_binary(path, blob):
    if os.path.exists(path):
        open(path, "ab").write(blob)


def recreate_exclusive(path):
    if os.path.exists(path):
        os.remove(path)
        open(path, "x").close()
