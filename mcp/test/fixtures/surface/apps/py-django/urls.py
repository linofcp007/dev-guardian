from django.conf import settings
from django.urls import include, path, re_path

from . import views

urlpatterns = [
    path("django/orders/", views.orders, name="orders"),
    path("django/orders/<int:order_id>/", views.order_detail, name="order-detail"),
    re_path(r"^django/legacy/(?P<slug>[\w-]+)/$", views.legacy, name="legacy"),
    # A computed path. It must survive as a route flagged path_partial: it is
    # real surface, but we cannot say what URL it is served at.
    path(settings.ADMIN_URL, views.admin_site, name="admin"),
    path("django/api/", include("api.urls")),
]
