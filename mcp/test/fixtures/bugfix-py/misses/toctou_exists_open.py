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
