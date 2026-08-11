"""Bait for the Django rule: a module-level helper named `path`.

`path(...)` is an ordinary function name. A rule that keys on the callee alone
reports every call here as an HTTP route, which is why the Django rule is
anchored to a `urlpatterns` list instead.
"""

import os
from pathlib import Path


def path(*parts):
    """Join filesystem path segments. Nothing to do with URLs."""
    return os.path.join(*parts)


def re_path(pattern, root="."):
    """Same bait for the second alternative of the Django rule."""
    return Path(root).glob(pattern)


CONFIG_FILE = path("etc", "app.ini")
TEMPLATE_ROOT = Path(path("var", "templates"))
LEGACY_FILES = list(re_path("*.cfg"))
