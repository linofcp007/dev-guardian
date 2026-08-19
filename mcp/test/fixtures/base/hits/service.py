"""Hits for the four Python rules in base.yml.

`py-shell-true` carries three call shapes rather than one because the rule is
`subprocess.$F(..., shell=True, ...)`: `$F` is a metavariable over the function
name, and the two `...` have to absorb a leading positional argument and a
trailing keyword argument respectively. One fixture would leave the `...` on
either side unexercised, and a `...` that never had to match anything is a
clause that could be deleted without a test moving.
"""

import pickle
import subprocess

import yaml


def run_user_code(source):
    eval(source)
    exec(source)


def spawn(cmd):
    subprocess.run(cmd, shell=True)
    subprocess.call("ls -la /tmp", shell=True)
    subprocess.Popen(cmd, shell=True, cwd="/tmp")


def load_config(stream):
    return yaml.load(stream)


def restore(handle, blob):
    first = pickle.load(handle)
    second = pickle.loads(blob)
    return first, second


def load_config_unsafely(stream):
    """The five unsafe spellings a one-argument `yaml.load($X)` never saw. Each
    of them executes arbitrary code from the document, exactly as the bare call
    does; `Loader=` is not a safety marker, the LOADER CLASS is."""
    a = yaml.load(stream, Loader=yaml.Loader)
    b = yaml.load(stream, Loader=yaml.UnsafeLoader)
    c = yaml.load(stream, yaml.Loader)
    d = yaml.unsafe_load(stream)
    e = yaml.full_load(stream)
    return a, b, c, d, e
