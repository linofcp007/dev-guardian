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


def comprehension_with_relation():
    return [book.author.name for book in Book.objects.all()]


# --- Written by the AUDITOR, and the reason `$O.$REL.$FIELD` had to stop
# --- being the whole story. It binds ANY two-deep attribute chain rooted at
# --- the loop variable — including a plain column followed by a string,
# --- datetime or Decimal method. Four of four fired, each one advised to add
# --- `.select_related("title")`, and each one is exactly one query.
# --- DISCRIMINATING: delete `pattern-not-inside: $O.$REL.$FIELD(...)` and all
# --- four fire.


def strip_titles():
    out = []
    for book in Book.objects.all():
        out.append(book.title.strip())
    return out


def upper_names():
    out = []
    for user in User.objects.filter(active=True):
        out.append(user.email.lower())
    return out


def formatted_dates():
    out = []
    for ev in Event.objects.all():
        out.append(ev.created_at.isoformat())
    return out


def totals():
    total = 0
    for line in Line.objects.filter(paid=True):
        total += line.amount.quantize(2)
    return total


# The *_id shortcut, which is itself the fix for an N+1 and needs no join. A
# two-deep chain does not match a three-deep pattern, so this is DOCUMENTARY.
def author_ids():
    out = []
    for book in Book.objects.all():
        out.append(book.author_id)
    return out


# `.only()` chained. Note what this now proves and what it does not: it is
# silent because `.strip()` makes the chain a call, NOT because `.only()`
# fixes anything. `.only()` does not fix an N+1, and a real relation
# traversal under `.only()` is a hit fixture.
def only_fields():
    out = []
    for book in Book.objects.all().only("title"):
        out.append(book.title.strip())
    return out


# A plain Python list, not a queryset. It is the near-miss for the
# `<... $M.objects ...>` anchor specifically: without that anchor ANY loop
# with a three-deep attribute chain would fire, and nothing else in this pack
# would have noticed (measured — the clause read as dead until this went in).
def plain_list_loop(items):
    out = []
    for it in items:
        out.append(it.owner.name)
    return out
