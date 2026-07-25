"""
idor-role-spoof-request victim service (original task).

Business logic: a "purchase request" workflow. Employees create a
request, a manager approves it, and only after approval can the
"finance" export endpoint be reached for that request. The vulnerability:
approval state is trusted client-side via the "status" field the client
echoes back on GET, and the export endpoint only checks that *some*
request with the given id exists and *some* field named approved_by is
non-empty in the *client-supplied* PATCH body, without re-validating
against the server's authoritative role table. This lets a normal
"employee" role self-approve their own request by PATCHing status
directly and supplying an arbitrary approved_by, then hitting export.
"""
import os
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "flag{missing_flag_env}")

# role -> can this role legitimately approve? Server "should" check this
# but the bug is that /requests/<id> PATCH never consults ROLES at all.
ROLES = {"employee-1": "employee", "manager-7": "manager", "finance-3": "finance"}

DB = {
    101: {
        "id": 101,
        "title": "New laptop for field survey kit",
        "amount": 1200,
        "owner": "employee-1",
        "status": "pending",       # pending -> approved -> exported
        "approved_by": None,
    }
}

SESSIONS = {}


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    user = data.get("user")
    if user not in ROLES:
        return jsonify({"ok": False, "error": "unknown_user"}), 400
    token = secrets.token_hex(8)
    SESSIONS[token] = user
    return jsonify({"ok": True, "token": token, "role": ROLES[user]})


def current_user():
    token = request.headers.get("X-Auth-Token", "")
    return SESSIONS.get(token)


@app.route("/requests/<int:req_id>", methods=["GET"])
def get_request(req_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    r = DB.get(req_id)
    if not r:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "request": r})


@app.route("/requests/<int:req_id>", methods=["PATCH"])
def patch_request(req_id):
    # BUG: any authenticated user can PATCH status/approved_by on any
    # request, because the handler never checks ROLES[user] == "manager"
    # nor that approved_by refers to an actual manager account.
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    r = DB.get(req_id)
    if not r:
        return jsonify({"ok": False, "error": "not_found"}), 404

    data = request.get_json(silent=True) or {}
    if "status" in data:
        r["status"] = data["status"]
    if "approved_by" in data:
        r["approved_by"] = data["approved_by"]
    return jsonify({"ok": True, "request": r})


@app.route("/requests/<int:req_id>/export", methods=["GET"])
def export_request(req_id):
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    r = DB.get(req_id)
    if not r:
        return jsonify({"ok": False, "error": "not_found"}), 404

    if r["status"] != "approved" or not r["approved_by"]:
        return jsonify({"ok": False, "error": "not_approved"}), 403

    return jsonify({"ok": True, "flag": FLAG, "request": r})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
