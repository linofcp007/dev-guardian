from django.urls import path, re_path, include
from django.contrib import admin
from . import views

urlpatterns = [
    # P20 control — imported bare name
    path("orders/", views.orders),
    # P21 re_path
    re_path(r"^legacy/(?P<slug>[\w-]+)/$", views.legacy),
    # P22 include (a mount, not a route)
    path("api/", include("app.api.urls")),
    # P23 django.urls.path written fully-qualified
    path("admin/", admin.site.urls),
]

# P24 modern DRF router registration
from rest_framework.routers import DefaultRouter
drf = DefaultRouter()
drf.register(r"widgets", views.WidgetViewSet, basename="widget")
urlpatterns += drf.urls
