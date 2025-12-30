import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Find app.py anywhere inside the repo (one level down or deeper)
matches = list(ROOT.rglob("app.py"))

assert matches, f"app.py not found anywhere under: {ROOT}"

app_py = matches[0]
sys.path.insert(0, str(app_py.parent))

from app import app


def test_homepage():
    client = app.test_client()
    res = client.get("/")
    assert res.status_code in (200, 302)
