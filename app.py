"""
DWT Delta Exchange Proxy Server
Fixed IP proxy for Delta Exchange API
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import hmac
import hashlib
import time
import os

app = Flask(__name__)
CORS(app)

DELTA_BASE = "https://api.india.delta.exchange"


def generate_signature(api_secret, method, path, query_string, body):
    timestamp = str(int(time.time()))
    # Delta signature includes '?' before query string if query exists
    if query_string:
        message = method + timestamp + path + "?" + query_string + body
    else:
        message = method + timestamp + path + body
    signature = hmac.new(
        api_secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return timestamp, signature


@app.route("/")
def index():
    return jsonify({
        "status": "ok",
        "service": "DWT Delta Proxy",
        "routes": ["/health", "/myip", "/test", "/delta/v2/..."]
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "DWT Delta Proxy",
        "timestamp": int(time.time())
    })


@app.route("/myip")
def myip():
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=5)
        ip = r.json()["ip"]
    except Exception:
        try:
            r = requests.get("https://checkip.amazonaws.com/", timeout=5)
            ip = r.text.strip()
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({
        "ip_to_whitelist": ip,
        "message": "Add this IP to your Delta Exchange API key whitelist. This IP is fixed."
    })


@app.route("/test")
def test():
    api_key    = request.headers.get("X-Api-Key",    "").strip()
    api_secret = request.headers.get("X-Api-Secret", "").strip()

    if not api_key or not api_secret:
        return jsonify({"error": "Send X-Api-Key and X-Api-Secret headers"}), 400

    path = "/v2/profile"
    timestamp, signature = generate_signature(api_secret, "GET", path, "", "")

    try:
        resp = requests.get(
            DELTA_BASE + path,
            headers={
                "Accept":    "application/json",
                "api-key":   api_key,
                "timestamp": timestamp,
                "signature": signature,
            },
            timeout=10
        )
        data = resp.json()
        return jsonify({
            "http_status":    resp.status_code,
            "success":        data.get("success", False),
            "delta_response": data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/debug")
def debug():
    """
    Test signing with exact params from the error message.
    Call: /debug?api_key=YOUR_KEY&api_secret=YOUR_SECRET
    Shows exactly what string we sign and what signature we produce.
    """
    api_key    = request.args.get("api_key",    "").strip()
    api_secret = request.args.get("api_secret", "").strip()

    if not api_key or not api_secret:
        return jsonify({"error": "Pass ?api_key=...&api_secret=... in URL"}), 400

    # Replicate the exact call that fails
    path         = "/v2/fills"
    query_string = "page_size=50&start_time=1782844200&end_time=1785522599"
    body         = ""
    method       = "GET"
    timestamp    = str(int(time.time()))

    # What we sign
    message_with_q    = method + timestamp + path + "?" + query_string + body
    message_without_q = method + timestamp + path + query_string + body

    import hmac as hmac_mod, hashlib as hl
    sig_with_q = hmac_mod.new(
        api_secret.encode("utf-8"),
        message_with_q.encode("utf-8"),
        hl.sha256
    ).hexdigest()

    sig_without_q = hmac_mod.new(
        api_secret.encode("utf-8"),
        message_without_q.encode("utf-8"),
        hl.sha256
    ).hexdigest()

    return jsonify({
        "timestamp": timestamp,
        "with_question_mark": {
            "signed_string": message_with_q,
            "signature": sig_with_q
        },
        "without_question_mark": {
            "signed_string": message_without_q,
            "signature": sig_without_q
        },
        "note": "Compare the signed_string with what Delta shows in their error signature_data"
    })


@app.route("/delta/<path:endpoint>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(endpoint):
    api_key    = request.headers.get("X-Api-Key",    "").strip()
    api_secret = request.headers.get("X-Api-Secret", "").strip()

    if not api_key or not api_secret:
        return jsonify({"error": "Missing X-Api-Key or X-Api-Secret headers"}), 400

    path         = "/" + endpoint
    query_string = request.query_string.decode("utf-8")
    body         = request.get_data(as_text=True) or ""
    method       = request.method.upper()

    timestamp, signature = generate_signature(api_secret, method, path, query_string, body)

    # Log what we're signing for debugging
    if query_string:
        signed_str = method + timestamp + path + "?" + query_string + body
    else:
        signed_str = method + timestamp + path + body
    print(f"SIGNING: {signed_str[:100]}")
    print(f"SIG: {signature[:20]}...")

    headers = {
        "Accept":       "application/json",
        "Content-Type": "application/json",
        "api-key":      api_key,
        "timestamp":    timestamp,
        "signature":    signature,
    }

    url = DELTA_BASE + path
    if query_string:
        url += "?" + query_string

    try:
        resp = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body if body else None,
            timeout=20
        )

        try:
            data = resp.json()
        except Exception:
            return jsonify({"error": "Bad JSON from Delta", "raw": resp.text[:300]}), 502

        if isinstance(data.get("error"), dict):
            err = data["error"]
            if err.get("code") == "ip_not_whitelisted_for_api_key":
                ip = err.get("context", {}).get("client_ip", "unknown")
                return jsonify({
                    "error":           "ip_not_whitelisted",
                    "ip_to_whitelist": ip,
                    "message":         f"Add this IP to your Delta API key whitelist: {ip}"
                }), 403

        return jsonify(data), resp.status_code

    except requests.exceptions.Timeout:
        return jsonify({"error": "Delta API timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
