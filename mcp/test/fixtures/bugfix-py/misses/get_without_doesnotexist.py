import contextlib

from django.core.exceptions import ObjectDoesNotExist


def dotted(user_id):
    try:
        return User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return None


def imported(user_id):
    try:
        return User.objects.get(pk=user_id)
    except ObjectDoesNotExist:
        return None


def broad(user_id):
    try:
        return User.objects.get(pk=user_id)
    except Exception:
        return None


# --- Written by the AUDITOR. Six correctly-guarded shapes, six of which the
# --- shipped rule reported, because its three exclusions only recognised a
# --- handler with no `as` binding, no tuple and no `else`. The `as` spelling
# --- alone is at least as common as the bare form.
# ---
# --- Each is DISCRIMINATING: delete the exclusion clause that covers it and
# --- it fires.


def with_as(user_id):
    try:
        return User.objects.get(pk=user_id)
    except User.DoesNotExist as exc:
        log(exc)
        return None


def with_tuple(user_id):
    try:
        return User.objects.get(pk=user_id)
    except (User.DoesNotExist, User.MultipleObjectsReturned):
        return None


def imported_as(user_id):
    try:
        return User.objects.get(pk=user_id)
    except ObjectDoesNotExist as exc:
        log(exc)
        return None


def suppressed(user_id):
    with contextlib.suppress(User.DoesNotExist):
        return User.objects.get(pk=user_id)
    return None


def with_else(user_id):
    try:
        u = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return None
    else:
        return u.name


def base_exception_as(user_id):
    try:
        return User.objects.get(pk=user_id)
    except Exception as exc:
        log(exc)
        return None
