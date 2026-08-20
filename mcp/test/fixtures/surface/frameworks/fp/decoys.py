import os
# F20 a local helper named path (should NOT match; rule is qualified)
def path(*parts):
    return os.path.join(*parts)

urlpatterns = [path("etc", "hosts"), path("var", "log")]
