import django.urls

urlpatterns = [
    # P30 explicitly module-qualified call
    django.urls.path("qualified/", None),
    django.urls.re_path(r"^qual/$", None),
]
