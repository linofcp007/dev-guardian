import re


def version(text):
    return re.match(r"v(\d+)", text).group(1)


def build(text):
    return re.search(r"b(\d+)", text).group(0)
