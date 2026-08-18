def profile(user_id):
    return User.objects.get(pk=user_id)
