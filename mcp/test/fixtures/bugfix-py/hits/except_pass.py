def a(conn):
    try:
        conn.commit()
    except ValueError:
        pass


def b(conn):
    try:
        conn.commit()
    except ValueError as exc:
        pass


def c(conn):
    try:
        conn.commit()
    except ValueError as exc:
        ...


def d(conn):
    try:
        conn.commit()
    except ValueError:
        ...


def e(conn):
    try:
        conn.commit()
    except:
        pass
