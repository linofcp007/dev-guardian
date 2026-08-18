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


def for_own_field_only():
    names = []
    for book in Book.objects.all():
        names.append(book.title)
    return names


def comprehension_with_relation():
    return [book.author.name for book in Book.objects.all()]
