"""Tests for the evil-portal core (routing, probe table, templates, cred store).

The socket-serving adapter is exercised only indirectly; these cover the pure
logic the CLI and launcher depend on.
"""

from kestrel_pi import evilportal as ep


def test_is_probe_path():
    assert ep.is_probe_path("/generate_204")
    assert ep.is_probe_path("/hotspot-detect.html")
    assert ep.is_probe_path("/", "captive.apple.com")
    assert ep.is_probe_path("/anything", "connectivitycheck.gstatic.com")
    assert not ep.is_probe_path("/login")
    assert not ep.is_probe_path("/", "example.com")


def test_route_get_serves_portal():
    r = ep.route("GET", "/", {})
    assert r.status == 200 and "Guest Wi-Fi" in r.body and r.recorded is None


def test_route_probe_get_redirects_to_portal():
    # a captive probe must get a 302 redirect to the portal -- that is the
    # reliable trigger for the "Sign in to Wi-Fi" window (a bare 200 is not).
    r = ep.route("GET", "/generate_204", {},
                 host="connectivitycheck.gstatic.com", portal_ip="10.0.0.1")
    assert r.status == 302 and r.location == "http://10.0.0.1/"
    assert "10.0.0.1" in r.body            # meta-refresh fallback body
    # any non-portal path redirects too; a relative target when no IP is known
    assert ep.route("GET", "/favicon.ico", {}).location == "/"


def test_route_portal_paths_serve_the_page():
    for p in ("/", "/portal", "/index.html", "/login"):
        r = ep.route("GET", p, {})
        assert r.status == 200 and "<form" in r.body


def test_route_post_records_and_shows_done():
    fields = {"username": "alice", "password": "s3cret"}
    r = ep.route("POST", "/login", fields)
    assert r.status == 200 and r.recorded == fields
    assert "connected" in r.body.lower()
    # an empty POST falls through to the portal, records nothing
    assert ep.route("POST", "/login", {}).recorded is None


def test_templates_prefer_operator_dir(tmp_path):
    (tmp_path / "index.html").write_text("<h1>MY LAB PORTAL</h1>")
    assert "MY LAB PORTAL" in ep.render_portal(str(tmp_path))
    # done.html falls back to the built-in when absent
    assert "connected" in ep.render_done(str(tmp_path)).lower()
    # no dir at all -> neutral built-ins
    assert "Guest Wi-Fi" in ep.render_portal(None)


def test_cred_store_roundtrip(tmp_path):
    creds = str(tmp_path / "sub" / "creds.jsonl")       # dir created on write
    ep.record_cred(creds, {"username": "u", "password": "p"}, client="10.0.0.9",
                   now=1000.0)
    ep.record_cred(creds, {"email": "x@y.z"}, client="10.0.0.5", now=2000.0)
    got = ep.load_creds(creds)
    assert len(got) == 2
    assert got[0]["fields"]["password"] == "p" and got[0]["client"] == "10.0.0.9"
    assert "u" in ep.format_creds(got) and "x@y.z" in ep.format_creds(got)
    # absent file -> empty, and a formatted empty set is a friendly line
    assert ep.load_creds(str(tmp_path / "nope.jsonl")) == []
    assert "no submissions" in ep.format_creds([])
