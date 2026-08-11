"""Bait for the Django rule: a module-level helper named `path`.

`path(...)` is an ordinary function name. A rule that keys on the bare callee
reports every call here as an HTTP route, which is why the Django rule matches
the *qualified* callee — `django.urls.path($PATH, ...)` — so a local helper of
the same name does not match.
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
