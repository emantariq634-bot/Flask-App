import sys
import os

# Add the folder that contains app.py to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "Flask app"))

from app import app

def test_homepage():
    client = app.test_client()
    res = client.get("/")
    assert res.status_code in (200, 302)
