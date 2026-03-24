"""
Secure Flask Application - Mitigated Deserialization
=====================================================
This is the FIXED version of vulnerable_app.py.

Key mitigations applied:
  1. Replaced pickle with JSON for session data serialization.
  2. Replaced yaml.load()/FullLoader with yaml.safe_load().
  3. Added HMAC signing for cookie integrity (tamper detection).
  4. Added input validation and sanitization layer.

These changes eliminate the Remote Code Execution vectors while
preserving the same application functionality.
"""

import base64
import hashlib
import hmac
import json
import yaml
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-to-a-strong-random-secret"

# Signing key derived from the app secret (used for cookie HMAC)
SIGNING_KEY = hashlib.sha256(app.config["SECRET_KEY"].encode()).digest()

DEFAULT_PROFILE = {
    "username": "guest",
    "role": "viewer",
    "theme": "light",
}

# Allowed values for input validation
ALLOWED_ROLES = {"viewer", "editor", "admin"}
ALLOWED_THEMES = {"light", "dark", "system"}
MAX_USERNAME_LENGTH = 64


# ---------------------------------------------------------------------------
# Helper: HMAC-based cookie signing
# ---------------------------------------------------------------------------
def sign_data(data_bytes: bytes) -> str:
    """Return base64(data) + '.' + hex(hmac) so the server can verify integrity."""
    b64 = base64.b64encode(data_bytes).decode()
    signature = hmac.new(SIGNING_KEY, data_bytes, hashlib.sha256).hexdigest()
    return f"{b64}.{signature}"


def verify_and_load(signed: str) -> dict | None:
    """Verify HMAC, then JSON-decode. Returns None on any failure."""
    if "." not in signed:
        return None
    b64, sig = signed.rsplit(".", 1)
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return None
    expected = hmac.new(SIGNING_KEY, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None  # tampered
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Helper: Input validation
# ---------------------------------------------------------------------------
def sanitize_string(value: str, max_length: int = 256) -> str:
    """Strip dangerous characters and enforce length limit."""
    if not isinstance(value, str):
        return ""
    # Remove null bytes and control characters
    cleaned = "".join(ch for ch in value if ch.isprintable())
    return cleaned[:max_length]


def validate_profile(data: dict) -> dict:
    """Validate and sanitize profile fields. Returns a clean profile dict."""
    username = sanitize_string(data.get("username", ""), MAX_USERNAME_LENGTH)
    if not username:
        username = DEFAULT_PROFILE["username"]

    role = data.get("role", DEFAULT_PROFILE["role"])
    if role not in ALLOWED_ROLES:
        role = DEFAULT_PROFILE["role"]

    theme = data.get("theme", DEFAULT_PROFILE["theme"])
    if theme not in ALLOWED_THEMES:
        theme = DEFAULT_PROFILE["theme"]

    return {"username": username, "role": role, "theme": theme}


# ===========================================================================
# FIX 1 — JSON + HMAC instead of pickle for session cookie
# ===========================================================================
@app.route("/")
def index():
    return jsonify({
        "message": "Secure Deserialization Demo",
        "endpoints": {
            "/profile": "GET — reads a signed JSON session cookie (secure)",
            "/profile/update": "POST — sets a signed JSON session cookie (secure)",
            "/yaml/config": "POST — parses YAML config with safe_load (secure)",
        },
    })


@app.route("/profile", methods=["GET"])
def get_profile():
    """
    SECURE: Reads an HMAC-signed, JSON-encoded session cookie.
    - No pickle involved — JSON cannot execute arbitrary code.
    - HMAC prevents tampering — modified cookies are rejected.
    """
    cookie_data = request.cookies.get("session_data")

    if cookie_data is None:
        return jsonify({"profile": DEFAULT_PROFILE, "note": "No session cookie set."})

    profile = verify_and_load(cookie_data)
    if profile is None:
        return jsonify({"error": "Invalid or tampered session cookie."}), 403

    return jsonify({"profile": profile})


@app.route("/profile/update", methods=["POST"])
def update_profile():
    """
    SECURE: Serializes profile as JSON, signs with HMAC, stores in cookie.
    Input is validated before serialization.
    """
    data = request.get_json(force=True)
    profile = validate_profile(data)

    # ✅ SECURE — JSON serialization + HMAC signing
    serialized = sign_data(json.dumps(profile).encode())

    response = make_response(jsonify({"message": "Profile updated", "profile": profile}))
    response.set_cookie("session_data", serialized, httponly=True, samesite="Strict")
    return response


# ===========================================================================
# FIX 2 — yaml.safe_load() instead of yaml.load()
# ===========================================================================
@app.route("/yaml/config", methods=["POST"])
def yaml_config():
    """
    SECURE: Uses yaml.safe_load() which only supports basic YAML types.
    The !!python/object and !!python/object/apply tags are rejected,
    preventing arbitrary code execution.
    """
    raw_yaml = request.get_data(as_text=True)

    if not raw_yaml:
        return jsonify({"error": "Request body must contain YAML data."}), 400

    # Reject excessively large payloads
    if len(raw_yaml) > 10_000:
        return jsonify({"error": "Payload too large."}), 413

    try:
        # ✅ SECURE — safe_load only deserializes basic YAML types
        config = yaml.safe_load(raw_yaml)
        return jsonify({"parsed_config": config})
    except yaml.YAMLError as exc:
        return jsonify({"error": f"YAML parse error: {exc}"}), 400


# ===========================================================================
# FIX 3 — JSON-based API data exchange instead of pickle
# ===========================================================================
@app.route("/api/data", methods=["POST"])
def receive_data():
    """
    SECURE: Accepts plain JSON data. No deserialization of opaque blobs.
    """
    body = request.get_json(force=True)
    data = body.get("payload")

    if data is None:
        return jsonify({"error": "Missing 'payload' field."}), 400

    # ✅ SECURE — data is already parsed as JSON by Flask
    if not isinstance(data, (dict, list, str, int, float, bool)):
        return jsonify({"error": "Unsupported payload type."}), 400

    return jsonify({"received": data})


# ---------------------------------------------------------------------------
# Run the app
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Secure App — Mitigated Deserialization Demo")
    print("=" * 60 + "\n")
    app.run(debug=False, port=5001)
