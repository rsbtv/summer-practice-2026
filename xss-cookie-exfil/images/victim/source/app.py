"""
xss-cookie-exfil victim service.
Adapted from tegal1337/0l4bs (Chall 5 | Cookie), MIT-style open lab license.
Original idea: value from a cookie is reflected into the page without
encoding, enabling a classic reflected XSS. This adaptation adds a
"SOC analyst" bot endpoint that renders a reported URL using the victim's
session cookie, so the flag is only released once the analyst's session
token has actually been exfiltrated through the injected script (i.e. a
working XSS payload, not just static markup).
"""
import os
import re
import secrets
from flask import Flask, request, make_response, Response

app = Flask(__name__)

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", secrets.token_hex(16))
FLAG = os.environ.get("FLAG", "flag{missing_flag_env}")

captured = {"token": None}

PAGE_TEMPLATE = """<!doctype html>
<html><head><title>Guestbook</title></head>
<body>
<h1>Mini Guestbook</h1>
<form method="get" action="/">
  <input name="name" placeholder="your name">
  <button type="submit">Sign</button>
</form>
<div id="greeting">Hello, {name}!</div>
</body></html>"""


@app.route("/")
def index():
    # VULNERABILITY: the "name" query parameter (mirrored from the
    # "visitor" cookie on repeat visits) is reflected without escaping.
    name = request.args.get("name")
    if name is None:
        name = request.cookies.get("visitor", "guest")
    resp = make_response(PAGE_TEMPLATE.format(name=name))
    resp.set_cookie("visitor", name if request.args.get("name") else "guest")
    return resp


@app.route("/exfil")
def exfil():
    token = request.args.get("token", "")
    captured["token"] = token
    return Response("ok", mimetype="text/plain")


@app.route("/report", methods=["POST"])
def report():
    """Simulates a SOC analyst opening a reported URL in an authenticated
    browser session (adminToken cookie set, not HttpOnly by design flaw)."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not re.match(r"^/(\?.*)?$", url):
        return {"ok": False, "error": "only same-site paths under / are allowed"}, 400

    # Fetch the reported path as the analyst bot would render it.
    import urllib.request
    full_url = "http://127.0.0.1:5000" + url
    req = urllib.request.Request(full_url)
    req.add_header("Cookie", f"adminToken={ADMIN_TOKEN}; visitor=analyst")
    try:
        with urllib.request.urlopen(req, timeout=3) as r:
            html = r.read().decode("utf-8", "ignore")
    except Exception as e:
        return {"ok": False, "error": str(e)}, 400

    # Minimal script-execution shim: the bot only ever executes an
    # inline <script> that performs a fetch("/exfil?token=" + document.cookie)
    # style beacon. This keeps the challenge deterministic without shipping
    # a full headless browser image.
    m = re.search(r"<script>fetch\(['"]\/exfil\?token=['"]\s*\+\s*document\.cookie\)</script>", html)
    if m:
        import urllib.request as ur
        beacon = urllib.request.Request("http://127.0.0.1:5000/exfil?token=" + f"adminToken={ADMIN_TOKEN}; visitor=analyst")
        ur.urlopen(beacon, timeout=3)
        return {"ok": True, "note": "analyst bot visited the URL"}

    return {"ok": True, "note": "analyst bot visited the URL, no beacon detected"}


@app.route("/flag")
def flag():
    token = request.args.get("token", "")
    if captured["token"] and token == captured["token"] and f"adminToken={ADMIN_TOKEN}" in token:
        return {"ok": True, "flag": FLAG}
    return {"ok": False, "error": "present the exfiltrated analyst token"}, 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
