import requests


def defaulted(payload):
    return payload.get("name", "").strip()


def http_var(url):
    return requests.get(url).json()


def http_literal():
    return requests.get("https://example.test/x").json()


def http_session(session):
    return session.get("/x").json()


def http_client(self):
    return self.client.get("/x").json()


def http_httpx(httpx):
    return httpx.get("/x").json()


def http_aiohttp(aiohttp):
    return aiohttp.get("/x").json()


def http_urllib(urllib):
    return urllib.get("/x").json()


def guarded(payload):
    value = payload.get("name")
    if value is None:
        return ""
    return value.strip()
