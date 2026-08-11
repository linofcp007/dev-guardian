"""Flask app — inventário de rotas com acentuação proposital.

The non-ASCII characters above sit BEFORE every match in this file. Semgrep
reports byte offsets, so a recovery that sliced the file by UTF-16 code units
would return a shifted span and a confidently wrong path.
"""

import os

from flask import Flask, jsonify

app = Flask(__name__)

DATABASE_URL = os.environ["DATABASE_URL"]
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")


# Rota de verificação de saúde — usada pelo balanceador.
@app.route("/flask/health")
def health():
    return jsonify(ok=True, level=LOG_LEVEL)


@app.route("/flask/items/<int:item_id>", methods=["GET", "DELETE"])
def item(item_id):
    return jsonify(id=item_id, dsn=bool(DATABASE_URL))


def build_url(*parts):
    """Not a route: a helper that happens to join URL segments."""
    return "/".join(parts)
