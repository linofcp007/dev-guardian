import os
from fastapi import FastAPI, APIRouter, Depends

app = FastAPI()
router = APIRouter(prefix="/v2", tags=["v2"])

# P10 control
@app.get("/fa/health")
async def health():
    return {}

# P11 modern: response_model + status_code kwargs
@router.post("/fa/items", response_model=dict, status_code=201)
async def create(payload: dict):
    return payload

# P12 dependency injection
@router.get("/fa/items/{item_id}", dependencies=[Depends(lambda: None)])
async def get_item(item_id: int):
    return {}

# P13 api_route with methods
@app.api_route("/fa/multi", methods=["GET", "PUT"])
async def multi():
    return {}

# P14 include_router — FastAPI's mount equivalent
app.include_router(router, prefix="/api")

# P15 env
E1 = os.getenv("NO_DEFAULT_VAR")
E2 = os.getenv("WITH_DEFAULT", "x")
E3 = os.environ["HARD_VAR"]
E4 = os.environ.get("SOFT_VAR")
from os import environ
E5 = environ["BARE_VAR"]
