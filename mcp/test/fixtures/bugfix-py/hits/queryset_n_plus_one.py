def titles():
    names = []
    for book in Book.objects.all():
        names.append(book.author.name)
    return names


def active_titles():
    names = []
    for book in Book.objects.filter(active=True):
        names.append(book.author.name)
    return names
