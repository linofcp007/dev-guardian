import os

from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()

API_TOKEN = os.getenv("API_TOKEN", "")


@app.get("/fastapi/items")
async def list_items():
    return []


@app.post("/fastapi/items")
async def create_item(payload: dict):
    return payload


@router.delete("/fastapi/items/{item_id}")
async def delete_item(item_id: int):
    return {"deleted": item_id, "authorized": bool(API_TOKEN)}


@app.on_event("startup")
async def startup():
    """Not a route: a lifecycle hook whose decorator is not an HTTP verb."""
    return None
