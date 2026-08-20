from flask import Flask, Blueprint

app = Flask(__name__)
bp = Blueprint("api", __name__, url_prefix="/api")

# P01 classic (control)
@app.route("/health")
def health():
    return "ok"

# P02 with methods kwarg
@app.route("/items", methods=["GET", "POST"])
def items():
    return []

# P03 Flask 2.x verb shortcut — the modern idiom
@app.get("/items/<int:item_id>")
def item(item_id):
    return {}

@app.post("/items")
def create_item():
    return {}

# P04 blueprint route
@bp.route("/bp-items")
def bp_items():
    return []

# P05 add_url_rule (no decorator)
app.add_url_rule("/legacy", "legacy", lambda: "l")

# P06 MethodView / class-based
class ItemAPI:
    @app.route("/cbv")
    def get(self):
        return {}
