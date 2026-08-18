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
