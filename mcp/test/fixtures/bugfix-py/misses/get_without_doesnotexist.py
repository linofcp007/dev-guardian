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
