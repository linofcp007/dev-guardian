def a(conn):
    try:
        conn.commit()
    except ValueError as exc:
        log(exc)


def b(conn):
    try:
        conn.commit()
    except ValueError:
        raise


def c(conn):
    try:
        conn.commit()
    except ValueError:
        pass
        log("recovered")
