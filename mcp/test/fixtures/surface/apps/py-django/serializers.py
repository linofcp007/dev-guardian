# Fixture for guardian-import-python's named-relative form
# (`from .x import y`), which urls.py does not exercise — it only uses the
# bare-dot form (`from . import views`).
from .models import OrderSerializer


def serialize(order):
    return OrderSerializer(order).data
