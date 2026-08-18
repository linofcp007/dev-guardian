def selected():
    names = []
    for book in Book.objects.all().select_related("author"):
        names.append(book.author.name)
    return names


def prefetched():
    names = []
    for book in Book.objects.filter(active=True).prefetch_related("author"):
        names.append(book.author.name)
    return names


def own_field_only():
    return [book.title for book in Book.objects.all()]
