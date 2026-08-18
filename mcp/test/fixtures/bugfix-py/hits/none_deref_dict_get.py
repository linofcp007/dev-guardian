def name(payload):
    return payload.get("name").strip()


def nested(payload):
    return payload.get("meta").get("id")
