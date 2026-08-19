"""Near-misses for the Python rules.

`model.eval()` is the one that would have cost the most had it been wrong. It is
how every PyTorch codebase switches a network into inference mode, it appears
several times per training script, and py-eval-exec is an ERROR-tier rule — so a
pattern that matched a method call as well as a bare call would have made the
baseline pack unusable on any project that touches machine learning. It is
silent BECAUSE `eval(...)` is a plain call pattern and this is an attribute
call; a pattern of `$X.eval(...)`, or any regex over the text, flags all three.
"""

import ast
import json
import pickle
import subprocess

import yaml


def switch_to_inference(model, module):
    model.eval()
    self_ = module
    self_.eval()
    module.submodule.eval()


def parse_literal(user_input):
    return ast.literal_eval(user_input)


def spawn(cmd):
    # Silent BECAUSE the keyword VALUE is part of the pattern, not just the
    # keyword: `shell=True` is the injectable form and `shell=False` is the
    # default. A pattern of `subprocess.$F(..., shell=$V, ...)` flags both.
    subprocess.run(cmd, shell=False)
    subprocess.run(["ls", "-la"], check=True)


def load_config(stream):
    # The first is the function the rule's message tells you to use. The second
    # is silent BECAUSE `yaml.load($X)` binds exactly ONE argument — passing a
    # Loader is what makes the call safe, and it is also what makes the arity
    # wrong for the pattern. The rule gets the right answer here for a reason
    # that happens to coincide with the right one; see the audit report for the
    # Loader values this arity check also lets through.
    first = yaml.safe_load(stream)
    second = yaml.load(stream, Loader=yaml.SafeLoader)
    return first, second


def persist(obj):
    return json.dumps(pickle.dumps(obj).hex())


def exec_plan(plan):
    """A function whose NAME contains `exec`. Silent because the rule matches a
    call to `exec`, not a definition of something spelled similarly."""
    return plan
