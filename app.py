
import os
import re
import uuid
import plistlib
import tempfile
import subprocess

import psycopg2
from flask import Flask, Response, jsonify, abort
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

BASE_URL = os.environ["https://shenudid.vercel.app"].rstrip("/")
DATABASE_URL = os.environ["https://shenudid.vercel.app"]

CERT_PEM = os.environ["PROFILE_SIGNING_CERT_PEM"]
KEY_PEM = os.environ["PROFILE_SIGNING_KEY_PEM"]


def db():
    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require",
        cursor_factory=RealDictCursor
    )


def initialize_database():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id BIGSERIAL PRIMARY KEY,
                    udid TEXT UNIQUE NOT NULL,
                    ios_version TEXT NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)


def openssl(args, input_data=None):
    result = subprocess.run(
        ["openssl"] + args,
        input=input_data,
        capture_output=True,
        check=False
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.decode("utf-8", errors="replace")
        )

    return result.stdout


def sign_profile(profile_data):
    with tempfile.TemporaryDirectory() as folder:
        cert_path = os.path.join(folder, "cert.pem")
        key_path = os.path.join(folder, "key.pem")
        input_path = os.path.join(folder, "profile.plist")

        with open(cert_path, "w") as f:
            f.write(CERT_PEM)

        with open(key_path, "w") as f:
            f.write(KEY_PEM)

        with open(input_path, "wb") as f:
            f.write(profile_data)

        return openssl([
            "cms", "-sign",
            "-binary",
            "-nodetach",
            "-in", input_path,
            "-signer", cert_path,
            "-inkey", key_path,
            "-outform", "DER"
        ])


def apple_response(data):
    """
    Decode CMS-signed Apple device data.

    This checks CMS signature integrity, but does NOT establish
    that the signer certificate belongs to Apple.
    """
    with tempfile.TemporaryDirectory() as folder:
        input_path = os.path.join(folder, "request.der")
        output_path = os.path.join(folder, "request.plist")

        with open(input_path, "wb") as f:
            f.write(data)

        openssl([
            "cms", "-verify",
            "-binary",
            "-inform", "DER",
            "-in", input_path,
            "-noverify",
            "-out", output_path
        ])

        with open(output_path, "rb") as f:
            content = f.read()

    try:
        return plistlib.loads(content)
    except Exception:
        abort(400, "Invalid Apple device plist")


def make_profile_service(token):
    profile = {
        "PayloadType": "Profile Service",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.shenudid.profile-service",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadDisplayName": "ShenUDID",
        "PayloadDescription": "Collect iPhone UDID and iOS version",
        "PayloadOrganization": "ShenUDID",
        "PayloadContent": {
            "URL": f"{BASE_URL}/profile-service/{token}",
            "DeviceAttributes": ["UDID", "VERSION"],
            "Challenge": token
        }
    }

    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def make_final_profile():
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "com.shenudid.device",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadDisplayName": "ShenUDID",
        "PayloadDescription": "UDID registration completed",
        "PayloadOrganization": "ShenUDID"
    }

    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


@app.get("/")
def home():
    return jsonify({
        "name": "ShenUDID",
        "status": "online"
    })


@app.get("/health")
def health():
    try:
        initialize_database()
        openssl(["version"])
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.get("/install/<token>")
def install(token):
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
        abort(400, "Invalid enrollment token")

    try:
        initialize_database()
        profile = make_profile_service(token)
        signed = sign_profile(profile)

        return Response(
            signed,
            status=200,
            content_type="application/x-apple-aspen-config"
        )
    except Exception as e:
        app.logger.exception("Profile generation failed")
        return jsonify({"error": "Profile generation failed"}), 500


@app.route("/profile-service/<token>", methods=["POST"])
def profile_service(token):
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
        abort(400, "Invalid enrollment token")

    if not request_is_cms():
        abort(400, "Expected CMS-signed device request")

    try:
        initialize_database()

        raw = __import__("flask").request.get_data()
        if not raw:
            abort(400, "Empty device request")

        attributes = apple_response(raw)

        udid = str(attributes.get("UDID", "")).strip()
        version = str(attributes.get("VERSION", "")).strip()
        challenge = attributes.get("CHALLENGE")

        if isinstance(challenge, bytes):
            challenge = challenge.decode("utf-8", errors="ignore")

        if challenge != token:
            abort(403, "Invalid enrollment challenge")

        # UDID format: 40 hexadecimal characters.
        if not re.fullmatch(r"[0-9a-fA-F]{40}", udid):
            abort(400, "Invalid or missing UDID")

        if not version or len(version) > 40:
            abort(400, "Invalid or missing iOS version")

        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO devices (udid, ios_version)
                    VALUES (%s, %s)
                    ON CONFLICT (udid)
                    DO UPDATE SET
                        ios_version = EXCLUDED.ios_version
                """, (udid, version))

        signed = sign_profile(make_final_profile())

        return Response(
            signed,
            status=200,
            content_type="application/x-apple-aspen-config"
        )

    except Exception:
        app.logger.exception("Profile service request failed")
        return jsonify({
            "error": "Profile service request failed"
        }), 400


def request_is_cms():
    from flask import request

    content_type = request.headers.get("Content-Type", "")
    return (
        "application/pkcs7-signature" in content_type.lower()
        or "application/x-pkcs7-signature" in content_type.lower()
    )


@app.get("/admin/devices")
def admin_devices():
    from flask import request

    password = os.environ.get("ADMIN_PASSWORD")
    if not password or request.headers.get("X-Admin-Password") != password:
        abort(401)

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT udid, ios_version, created_at
                FROM devices
                ORDER BY created_at DESC
            """)
            rows = cur.fetchall()

    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    initialize_database()
    app.run(host="0.0.0.0", port=5000, debug=False)
