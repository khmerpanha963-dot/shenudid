
from flask import Flask, request, render_template_string, redirect, url_for, make_response
import plistlib
import json
import os
import re
import uuid
import secrets
from datetime import datetime, timezone
from urllib.parse import urlparse


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Set this to your real HTTPS website address.
BASE_URL = os.environ.get("BASE_URL", "https://shenudid.vercel.app).rstrip("/")

DATA_FILE = "udids.json"
TOKENS = {}

def save_udid(udid):
    records = []

    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                records = json.load(f)
        except (ValueError, OSError):
            records = []

    # Avoid saving duplicate UDIDs.
    if not any(item.get("udid") == udid for item in records):
        records.append({
            "udid": udid,
            "created_at": datetime.now(timezone.utc).isoformat()
        })

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)


def plist_response(data, filename=None):
    response = make_response(
        plistlib.dumps(data, fmt=plistlib.FMT_XML)
    )
    response.headers["Content-Type"] = "application/x-apple-aspen-config"
    if filename:
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )
    return response


HOME = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Panha UDID</title>
<style>
*{box-sizing:border-box}
body{
 margin:0;background:#f6f7f9;color:#202124;
 font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
nav{
 height:70px;background:white;border-bottom:1px solid #eee;
 display:flex;align-items:center;justify-content:space-between;
 padding:0 7%;
}
.logo{font-size:21px;font-weight:750;color:#171717}
.logo span{color:#3978e8}
.container{max-width:650px;margin:75px auto;padding:20px}
.card{
 background:white;border:1px solid #e9e9e9;border-radius:18px;
 padding:38px;box-shadow:0 8px 35px rgba(0,0,0,.035);
 text-align:center;
}
.icon{
 width:65px;height:65px;border-radius:18px;background:#edf3ff;
 display:flex;align-items:center;justify-content:center;
 margin:0 auto 22px;font-size:30px;
}
h1{font-size:32px;margin:0 0 12px}
p{color:#737780;line-height:1.7;font-size:15px}
button{
 width:100%;border:0;border-radius:10px;padding:16px;
 background:#3478f6;color:white;font-size:16px;
 font-weight:650;cursor:pointer;margin-top:18px;
}
button:hover{background:#2465db}
button:disabled{opacity:.5;cursor:not-allowed}
.notice{
 text-align:left;background:#f7f8fa;padding:17px;
 border-radius:10px;margin-top:24px;font-size:13px;
 color:#656b75;line-height:1.7;
}
.consent{
 display:flex;gap:10px;text-align:left;align-items:flex-start;
 margin-top:22px;font-size:13px;color:#555;
}
.consent input{margin-top:3px}
footer{text-align:center;color:#999;font-size:12px;margin-top:30px}
@media(max-width:600px){
 .container{margin:35px auto;padding:14px}
 .card{padding:28px 20px}
 h1{font-size:27px}
}
</style>
</head>
<body>
<nav>
 <div class="logo">Panha<span>UDID</span></div>
 <div style="font-size:13px;color:#777">iOS Device Service</div>
</nav>

<div class="container">
 <div class="card">
  <div class="icon">📱</div>
  <h1>Get Your iPhone UDID</h1>
  <p>
   Identify your Apple device with our simple UDID enrollment process.
   Open this page in Safari on your iPhone.
  </p>

  <form action="/start" method="POST">
   <label class="consent">
    <input type="checkbox" name="consent" value="yes" required>
    <span>
     I understand and consent to sharing my device UDID with
     Panha UDID for the purpose described on this page.
    </span>
   </label>
   <button type="submit">Get My UDID →</button>
  </form>

  <div class="notice">
   <b>Privacy information</b><br>
   Only your UDID is requested. IMEI, ICCID, contacts,
   photos and personal files are not requested.
   You can cancel the installation at any time.
  </div>
 </div>
 <footer>© 2026 Panha UDID. Device identification service.</footer>
</div>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HOME)


@app.route("/start", methods=["POST"])
def start():
    if request.form.get("consent") != "yes":
        return "Consent is required.", 400

    token = secrets.token_urlsafe(32)
    TOKENS[token] = True

    return redirect(url_for("download_profile", token=token))


@app.route("/profile/<token>.mobileconfig")
def download_profile(token):
    if not TOKENS.get(token):
        return "Invalid or expired enrollment session.", 403

    service_url = f"{BASE_URL}/profile-service/{token}"

    profile = {
        "PayloadContent": {
            "URL": service_url,
            "DeviceAttributes": [
                "UDID"
            ]
        },
        "PayloadDescription": "Requests permission to share your device UDID.",
        "PayloadDisplayName": "Panha UDID Enrollment",
        "PayloadIdentifier": "com.panhausid.profile-service",
        "PayloadOrganization": "Panha UDID",
        "PayloadType": "Profile Service",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadVersion": 1
    }

    return plist_response(profile, "PanhaUDID.mobileconfig")


@app.route("/profile-service/<token>", methods=["GET", "POST"])
def profile_service(token):
    if not TOKENS.get(token):
        return "Invalid enrollment session.", 403

    if request.method == "GET":
        return "Panha UDID enrollment service is ready."

    try:
        data = plistlib.loads(request.get_data())

        # Accept only the UDID attribute.
        udid = data.get("UDID")

        if not isinstance(udid, str):
            return "UDID was not supplied.", 400

        udid = udid.strip().upper()

        # Apple UDIDs are normally 40 hexadecimal characters.
        if not re.fullmatch(r"[0-9A-F]{40}", udid):
            return "Invalid UDID format.", 400

        save_udid(udid)
        TOKENS.pop(token, None)

        # Return an empty configuration profile response.
        response_profile = {
            "PayloadContent": [],
            "PayloadDisplayName": "Panha UDID",
            "PayloadIdentifier": "com.panhausid.response",
            "PayloadUUID": str(uuid.uuid4()),
            "PayloadVersion": 1
        }

        return plist_response(response_profile)

    except Exception:
        app.logger.exception("UDID enrollment failed")
        return "Unable to process enrollment.", 400


@app.route("/admin/udids")
def admin_udids():
    # Protect this endpoint before deploying publicly.
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if not admin_password:
        return "Admin access is not configured.", 503

    if request.headers.get("X-Admin-Password") != admin_password:
        return "Unauthorized", 401

    if not os.path.exists(DATA_FILE):
        return {"udids": []}

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return {"udids": json.load(f)}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
