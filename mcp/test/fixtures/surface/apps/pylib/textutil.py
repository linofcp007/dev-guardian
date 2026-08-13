"""A shared Python package at the project root, imported by py-fastapi/main.py.

The ONLY intra-project Python import in this fixture that can actually
resolve, and it exists for that reason. Python's absolute dotted form
(`from pylib.textutil import slugify`) names a path from the project root
down, so a package directory here has to carry a valid Python identifier —
`py-django`, `py-fastapi` and `py-flask` cannot be named by an `import`
statement at all, which is why they were never enough. py-django's
`serializers.py` keeps the RELATIVE form (`from .models import ...`), which
is unresolvable by design; this is its resolvable counterpart.

Adding, removing or renaming this file changes the pinned import-edge list in
mcp/test/e2e/rulePackFixture.test.ts and the Python reachability verdict in
mcp/test/e2e/validateFindingFixture.test.ts.
"""


def slugify(text):
    """Lower-case and hyphenate. No route, no env var, no framework."""
    return "-".join(text.lower().split())
