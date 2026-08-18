def load(path):
    try:
        return read_file(path)
    except OSError as exc:
        log(exc)
        raise
