"""Static UI files served from /."""
from __future__ import annotations


def test_root_returns_html_with_netmap_title(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "<title>net-map</title>" in r.text


def test_styles_css_served_under_ui(client):
    r = client.get("/ui/styles.css")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/css")


def test_app_js_served_under_ui(client):
    r = client.get("/ui/app.js")
    assert r.status_code == 200
    assert "javascript" in r.headers["content-type"]
