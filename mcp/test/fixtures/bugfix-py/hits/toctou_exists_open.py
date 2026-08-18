import os


def read_if_present(path):
    if os.path.exists(path):
        return open(path).read()
    return ""
