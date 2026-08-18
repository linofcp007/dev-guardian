import re


def version(text):
    found = re.match(r"v(\d+)", text)
    if found is None:
        return "0"
    return found.group(1)


def compiled(pattern, text):
    return pattern.finditer(text)
