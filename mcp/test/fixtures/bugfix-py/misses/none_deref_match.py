import re


def version(text):
    found = re.match(r"v(\d+)", text)
    if found is None:
        return "0"
    return found.group(1)


def compiled(pattern, text):
    return pattern.finditer(text)


# --- Written by the AUDITOR: the walrus guard, the modern spelling of the
# --- same check. DOCUMENTARY rather than discriminating — the rule has no
# --- exclusion clause at all, so no ablation can make this fire; it records
# --- that binding the match before using it is the fix the message asks for.
def walrus(text):
    if (m := re.match(r"v(\d+)", text)) is not None:
        return m.group(1)
    return "0"
