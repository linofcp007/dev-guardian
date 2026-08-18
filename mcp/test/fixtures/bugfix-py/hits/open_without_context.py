def dump(path, rows):
    handle = open(path, "w")
    for row in rows:
        handle.write(row)
