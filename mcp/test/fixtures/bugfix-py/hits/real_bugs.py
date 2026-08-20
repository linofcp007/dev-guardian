"""The REAL-BUGS CORPUS, written by the AUDITOR rather than by the rules'
author, and the structural answer to how a wave of false-positive work can
open a false-negative hole with a green suite.

Everything else in hits/ is one minimal instantiation per rule, written by
whoever wrote the rule. That proves a rule fires at all. It cannot prove that
an exclusion added later did not eat a real bug, because a minimal hit fixture
carries no guard shapes for an exclusion to catch on — and the near-miss
fixtures only ever measure the direction the exclusion was written for.

Every defect below was SILENT before this round, and each one sits next to the
guard shape its rule's exclusions match, so widening any of those exclusions
by one step turns this file red.
"""
import asyncio
import os
import pathlib
import re


# --- race-condition-toctou-exists-open: four spellings that dominate modern
# --- code and that the two-exact-function-names version could not see.


def toctou_isfile(path):
    if os.path.isfile(path):
        return open(path).read()
    return ""


def toctou_access(path):
    if os.access(path, os.R_OK):
        return open(path).read()
    return ""


def toctou_negated_guard(path):
    if not os.path.exists(path):
        return ""
    return open(path).read()


def toctou_pathlib(path):
    p = pathlib.Path(path)
    if p.exists():
        return p.open().read()
    return ""


# --- null-safety-none-deref-dict-get: two real dictionary bugs that the old
# --- receiver allow-list silenced by SUBSTRING. A Flask/Django session IS a
# --- dict, and `client_config` is not an HTTP client.


def session_user_id(session):
    return session.get("user_id").strip()


def client_timeout(client_config):
    return client_config.get("timeout").total_seconds()


# --- null-safety-none-deref-match: three accessors that blow up in exactly
# --- the same way as `.group()` and were all silent.


def match_groups(text):
    return re.match(r"v(\d+)", text).groups()


def match_subscript(text):
    return re.match(r"v(\d+)", text)[1]


def match_span_start(text):
    return re.search(r"\d+", text).start()


# --- off-by-one-range-len-plus-one: the explicit-start spelling. The arity of
# --- `range` is part of the pattern, so `range(0, n + 1)` was invisible.


def explicit_start(values):
    acc = 0
    for i in range(0, len(values) + 1):
        acc += values[i]
    return acc


# --- edge-case-queryset-n-plus-one: a real N+1 behind `.exclude()`, and a
# --- real N+1 behind `.only()`. Both were silent, and for the wrong reason:
# --- ANY chained call broke the `$M.objects.all()` anchor, so the pack's
# --- `select_related` near-misses would have stayed green against a
# --- deliberately broken rule.


def n_plus_one_behind_exclude():
    out = []
    for book in Book.objects.exclude(draft=True):
        out.append(book.author.name)
    return out


def n_plus_one_behind_only():
    out = []
    for book in Book.objects.all().only("title"):
        out.append(book.author.name)
    return out


# --- error-handling-get-without-doesnotexist: an UNGUARDED get inside the
# --- `except` arm. The guard protects the `try` arm and nothing else, but a
# --- pattern-not-inside suppresses the whole try node, so this was silenced
# --- by the very guard that does not cover it.


def unguarded_in_except(user_id, fallback_id):
    try:
        return User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return Profile.objects.get(pk=fallback_id)


# --- error-handling-except-pass and -bare-except: adding a `finally:`, an
# --- `else:` or a second exception type to the SAME swallowing `try`
# --- silenced both rules completely. Four swallows, unchanged in substance.


def pass_with_tuple(conn):
    try:
        conn.commit()
    except (ValueError, TypeError):
        pass


def pass_with_finally(conn):
    try:
        conn.commit()
    except ValueError:
        pass
    finally:
        conn.close()


def bare_with_finally(path):
    try:
        return read(path)
    except:
        return None
    finally:
        cleanup()


def bare_with_else(path):
    try:
        v = read(path)
    except:
        return None
    else:
        return v


# --- error-handling-get-without-doesnotexist, the other direction: the try
# --- exists but the handler does NOT guard the miss. Each of the three
# --- exclusion clauses carries a metavariable-regex that filters the caught
# --- TYPE, and without one of these three the filter is dead — the exclusion
# --- would be "any try/except at all silences the rule".


def get_in_try_wrong_handler(user_id):
    try:
        return User.objects.get(pk=user_id)
    except ValueError:
        return None


def get_in_try_wrong_handler_as(user_id):
    try:
        return User.objects.get(pk=user_id)
    except ValueError as exc:
        log(exc)
        return None


def get_in_try_wrong_handler_else(user_id):
    try:
        u = User.objects.get(pk=user_id)
    except ValueError:
        return None
    else:
        return u.name


# --- error-handling-except-pass: one function per remaining handler-shape x
# --- try-shape combination. Ablation found five of the nine branches dead
# --- without them, and a branch nothing exercises can be deleted while the
# --- suite stays green — which is how "add `else:` and the rule goes quiet"
# --- gets reintroduced.


def pass_with_else(conn):
    try:
        conn.commit()
    except ValueError:
        pass
    else:
        conn.log()


def pass_as_with_finally(conn):
    try:
        conn.commit()
    except ValueError as exc:
        pass
    finally:
        conn.close()


def pass_as_with_else(conn):
    try:
        conn.commit()
    except ValueError as exc:
        pass
    else:
        conn.log()


def bare_pass_with_finally(conn):
    try:
        conn.commit()
    except:
        pass
    finally:
        conn.close()


def bare_pass_with_else(conn):
    try:
        conn.commit()
    except:
        pass
    else:
        conn.log()


# --- null-safety-none-deref-match: the three remaining accessors. Ablation
# --- found their branches dead without a fixture each.


def match_groupdict(text):
    return re.search(r"(?P<n>\d+)", text).groupdict()


def match_end(text):
    return re.search(r"\d+", text).end()


def match_span(text):
    return re.search(r"\d+", text).span()


# --- race-condition-toctou-exists-open: the negated `isfile` guard. One
# --- branch per guard spelling, and this one had no fixture behind it.


def toctou_negated_isfile(path):
    if not os.path.isfile(path):
        return ""
    return open(path).read()


# --- memory-leak-open-without-context: a leaked handle in the same function
# --- as one whose ownership is transferred. The rule carries eight exclusion
# --- clauses and had no corpus entry at all; every one of those clauses
# --- unifies on the handle variable, and widening any of them to "some
# --- handle in this function escapes" would swallow this.


def leak_beside_transfer(path, rows):
    kept = open(path)
    leaked = open(path + ".log", "w")
    for row in rows:
        leaked.write(row)
    return kept


# --- race-condition-asyncio-not-awaited: an un-awaited coroutine in the same
# --- function as an awaited one, for the same reason.


async def unawaited_beside_awaited(task):
    await asyncio.sleep(1)
    asyncio.wait_for(task, timeout=5)
    return "done"
