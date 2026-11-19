"""Every route the app serves must have a rule in ACCESS.md.

This is the safety net the access-guard skill writes into projects: a new
route nobody wrote a rule for fails here instead of shipping open.
"""

import re
from pathlib import Path

from fastapi.routing import APIRoute

from app import app

ACCESS_MD = Path(__file__).resolve().parents[1] / "ACCESS.md"


def test_every_route_has_an_access_rule():
    documented = set(re.findall(r"`(GET|POST|PUT|PATCH|DELETE) ([^`]+)`", ACCESS_MD.read_text(encoding="utf-8")))
    served = {
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods - {"HEAD"}
    }
    assert sorted(served - documented) == []
