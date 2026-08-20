import queue

import requests


def defaulted(payload):
    return payload.get("name", "").strip()


def http_var(url):
    return requests.get(url).json()


def http_literal():
    return requests.get("https://example.test/x").json()


def http_session(session):
    return session.get("/x").json()


def http_client(self):
    return self.client.get("/x").json()


def guarded(payload):
    value = payload.get("name")
    if value is None:
        return ""
    return value.strip()


# --- Written by the AUDITOR. `$D` bound anything at all with a one-argument
# --- `.get`, so eight of these fired at ERROR. The discrimination that works
# --- is the KEY, not the receiver: a dictionary lookup uses a string literal,
# --- while the ORM uses a kwarg or a pk, `queue.Queue` uses a bool/timeout,
# --- and a registry uses an enum. Each is DISCRIMINATING: drop the
# --- metavariable-regex on the key and it fires.


# Django's Manager.get RAISES DoesNotExist; it never returns None, and it has
# no default parameter, so the advice the shipped rule printed here could not
# be followed. The try/except is what keeps the sibling
# `get-without-doesnotexist` rule quiet — the two used to fire on the same
# line with contradictory advice.
def orm_positional(user_id):
    try:
        return User.objects.get(user_id).delete()
    except User.DoesNotExist:
        return None


def orm_manager(book):
    try:
        return book.authors.get(pk=1).save()
    except Author.DoesNotExist:
        return None


# queue.Queue.get() blocks and returns an item; it never returns None.
def queue_get(q):
    return q.get(True).process()


def queue_get_timeout():
    q = queue.Queue()
    return q.get(timeout=1).process()


# An import-time registry keyed by an enum: `.get(kind)` cannot miss.
HANDLERS = {}


def dispatch(kind, ev):
    return HANDLERS.get(kind).handle(ev)


# HTTP clients whose receiver name is NOT in the old allow list. The key is a
# variable, so none of them is a dictionary lookup.
def http_via_urllib3(pool, url):
    return pool.get(url).json()


def http_via_api(api, path):
    return api.get(path).json()


def http_via_conn(conn, path):
    return conn.get(path).json()


# Guarded by a membership test, and by an assert. Both are correct by
# construction, and both are DISCRIMINATING for their own exclusion clause.
def guarded_by_membership(payload):
    if "name" in payload:
        return payload.get("name").strip()
    return ""


def guarded_by_assert(payload):
    assert "name" in payload
    return payload.get("name").strip()
