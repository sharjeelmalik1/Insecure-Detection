"""
Vulnerable Flask Application - Insecure Deserialization Demo
=============================================================
WARNING: This application is INTENTIONALLY VULNERABLE for educational purposes.
         NEVER deploy this in production or on a public network.

Demonstrates two common insecure deserialization patterns:
  1. pickle.loads() on user-controlled input (session cookies, API data)
  2. yaml.load() with the unsafe default Loader on user-controlled input

Both allow arbitrary code execution when an attacker crafts a malicious payload.
"""

import base64
import pickle
import yaml
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)
app.config["SECRET_KEY"] = "insecure-demo-key"


# ---------------------------------------------------------------------------
# Helper: simulated user profile store
# ---------------------------------------------------------------------------
DEFAULT_PROFILE = {
    "username": "guest",
    "role": "viewer",
    "theme": "light",
}


# ===========================================================================
# VULNERABILITY 1 — pickle.loads() on user-controlled cookie
# ===========================================================================
@app.route("/")
def index():
    """Landing page that explains available endpoints."""
    return jsonify({
        "message": "Vulnerable Deserialization Demo",
        "endpoints": {
            "/profile": "GET — reads a pickled session cookie (vulnerable)",
            "/profile/update": "POST — sets a pickled session cookie (vulnerable)",
            "/yaml/config": "POST — parses YAML config from request body (vulnerable)",
        },
        "warning": "This app is intentionally vulnerable. Do NOT expose to the internet.",
    })


@app.route("/profile", methods=["GET"])
def get_profile():
    """
    VULNERABLE: Reads a base64-encoded, pickled user profile from a cookie.
    An attacker can replace the cookie value with a malicious pickle payload
    to achieve Remote Code Execution (RCE).
    """
    cookie_data = request.cookies.get("session_data")

    if cookie_data is None:
        return jsonify({"profile": DEFAULT_PROFILE, "note": "No session cookie set."})

    try:
        # ⚠️  INSECURE — pickle.loads on untrusted data
        raw = base64.b64decode(cookie_data)
        profile = pickle.loads(raw)  # nosec B301 — intentionally vulnerable
        return jsonify({"profile": profile})
    except Exception as exc:
        return jsonify({"error": f"Failed to deserialize profile: {exc}"}), 400


@app.route("/profile/update", methods=["POST"])
def update_profile():
    """
    Accepts JSON fields and stores them as a pickled, base64-encoded cookie.
    This simulates a real-world pattern where session state is serialized
    into a client-side cookie.
    """
    data = request.get_json(force=True)
    profile = {
        "username": data.get("username", DEFAULT_PROFILE["username"]),
        "role": data.get("role", DEFAULT_PROFILE["role"]),
        "theme": data.get("theme", DEFAULT_PROFILE["theme"]),
    }

    # ⚠️  INSECURE — pickle.dumps sent to client who can tamper with it
    serialized = base64.b64encode(pickle.dumps(profile)).decode()

    response = make_response(jsonify({"message": "Profile updated", "profile": profile}))
    response.set_cookie("session_data", serialized)
    return response


# ===========================================================================
# VULNERABILITY 2 — yaml.load() with unsafe Loader
# ===========================================================================
@app.route("/yaml/config", methods=["POST"])
def yaml_config():
    """
    VULNERABLE: Accepts raw YAML from the request body and deserializes it
    using yaml.load() without specifying a safe Loader.

    An attacker can embed !!python/object or !!python/object/apply tags
    to execute arbitrary Python code on the server.
    """
    raw_yaml = request.get_data(as_text=True)

    if not raw_yaml:
        return jsonify({"error": "Request body must contain YAML data."}), 400

    try:
        # ⚠️  INSECURE — yaml.load with UnsafeLoader (allows arbitrary Python objects)
        config = yaml.load(raw_yaml, Loader=yaml.UnsafeLoader)  # nosec B506
        return jsonify({"parsed_config": str(config)})
    except Exception as exc:
        return jsonify({"error": f"YAML parse error: {exc}"}), 400


# ===========================================================================
# VULNERABILITY 3 — pickle via API body (simulates data exchange)
# ===========================================================================
@app.route("/api/data", methods=["POST"])
def receive_data():
    """
    VULNERABLE: Accepts base64-encoded pickled data in the JSON body.
    Simulates an internal micro-service API that trusts serialized data
    from another service — a common real-world anti-pattern.
    """
    body = request.get_json(force=True)
    encoded = body.get("payload")

    if not encoded:
        return jsonify({"error": "Missing 'payload' field."}), 400

    try:
        raw = base64.b64decode(encoded)
        # ⚠️  INSECURE — pickle.loads on untrusted API input
        data = pickle.loads(raw)  # nosec B301 — intentionally vulnerable
        return jsonify({"received": str(data)})
    except Exception as exc:
        return jsonify({"error": f"Deserialization failed: {exc}"}), 400


# ---------------------------------------------------------------------------
# Run the app
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  ⚠️  VULNERABLE APP — FOR EDUCATIONAL USE ONLY")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000)
