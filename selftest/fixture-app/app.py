"""A tiny web app the kit's self-test plants defects into. Not a real product.

It uses the kit's own header template, so the self-test also proves the
template works.
"""

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "templates" / "headers"))
from fastapi_security_headers import SecurityHeadersMiddleware  # noqa: E402

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SecurityHeadersMiddleware)  # security-headers


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    return (
        '<!doctype html><html lang="en"><head><title>Fixture</title></head>'
        '<body><a href="/items/1">Item 1</a></body></html>'
    )


@app.get("/items/{item_id}")
def read_item(item_id: int) -> dict:
    return {"id": item_id, "name": f"Item {item_id}"}
