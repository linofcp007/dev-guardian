import os


def read_if_present(path):
    if os.path.exists(path):
        return open(path).read()
    return ""


def read_after_logging(path):
    if os.path.exists(path):
        log("found")
        return open(path).read()
    return ""
