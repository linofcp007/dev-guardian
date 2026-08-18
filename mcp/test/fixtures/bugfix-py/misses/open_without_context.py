def managed(path, rows):
    with open(path, "w") as handle:
        for row in rows:
            handle.write(row)


def explicit(path, rows):
    handle = open(path, "w")
    try:
        for row in rows:
            handle.write(row)
    finally:
        handle.close()


class Writer:
    def __init__(self, path):
        self.handle = open(path, "w")

    def close(self):
        self.handle.close()
