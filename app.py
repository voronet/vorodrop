import os
import uuid
import json
import time
import threading
import random
import argparse
import secrets
import hmac
import csv
from datetime import datetime, timedelta
from flask import Flask, request, render_template_string, send_file, abort, redirect, url_for, session, jsonify
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

# ================= CONFIG =================
UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", "/mnt/drop")
MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024  # 4GB
CLEANUP_INTERVAL = 60
UPLOAD_PASSWORD = b"test123"
WORDLIST = ["sun", "moon", "river", "tree", "cloud", "stone", "shadow",
            "ember", "wolf", "falcon", "ocean", "storm", "forest",
            "night", "dawn", "echo", "flame", "wind"]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATS_CSV = os.path.join(SCRIPT_DIR, "usage_statistics.csv")

CSV_FIELDNAMES = [
    "upload_time",
    "ip",
    "user_agent",
    "filename",
    "size_bytes",
    "expiry_choice",
    "expiry_datetime",
    "folder_uuid",
    "short_word",
    "password_protected",
    "download_count",
]

# ==========================================

parser = argparse.ArgumentParser()
parser.add_argument("--secure", action="store_true", help="Enable secure upload mode")
args = parser.parse_args()
SECURE_MODE = args.secure

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
app.wsgi_app = ProxyFix(app.wsgi_app)

os.makedirs(UPLOAD_ROOT, exist_ok=True)

short_links = {}
failed_attempts = {}

# ================= CSV TELEMETRY =================

def init_csv():
    """Create the CSV file with headers if it doesn't already exist."""
    if not os.path.exists(STATS_CSV):
        with open(STATS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()

def log_upload(ip, user_agent, filename, size_bytes, expiry_choice, expiry_datetime, folder_uuid, short_word, password_protected):
    """Append one row to usage_statistics.csv."""
    row = {
        "upload_time":       datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":                ip,
        "user_agent":        user_agent,
        "filename":          filename,
        "size_bytes":        size_bytes,
        "expiry_choice":     expiry_choice,
        "expiry_datetime":   expiry_datetime.strftime("%Y-%m-%d %H:%M:%S"),
        "folder_uuid":       folder_uuid,
        "short_word":        short_word,
        "password_protected": "yes" if password_protected else "no",
        "download_count":    0,
    }
    with open(STATS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writerow(row)

def increment_download_count(folder_uuid):
    """Find the row matching folder_uuid and increment its download_count in-place."""
    if not os.path.exists(STATS_CSV):
        return
    rows = []
    with open(STATS_CSV, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["folder_uuid"] == folder_uuid:
                row["download_count"] = int(row.get("download_count", 0)) + 1
            rows.append(row)
    with open(STATS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

init_csv()

# ================= CLEANUP THREAD =================
def cleanup_expired():
    while True:
        now = datetime.utcnow()
        for folder in os.listdir(UPLOAD_ROOT):
            folder_path = os.path.join(UPLOAD_ROOT, folder)
            meta_path = os.path.join(folder_path, "meta.json")
            if os.path.exists(meta_path):
                with open(meta_path) as f:
                    meta = json.load(f)
                expiry = datetime.fromisoformat(meta["expiry"])
                if now > expiry:
                    try:
                        for file in os.listdir(folder_path):
                            os.remove(os.path.join(folder_path, file))
                        os.rmdir(folder_path)
                    except:
                        pass
        time.sleep(CLEANUP_INTERVAL)

threading.Thread(target=cleanup_expired, daemon=True).start()

# ================= UTIL =================
def generate_short_word():
    while True:
        word = random.choice(WORDLIST)
        if word not in short_links:
            return word

def expiration_from_choice(choice):
    mapping = {
        "1m":  timedelta(minutes=1),
        "5m":  timedelta(minutes=5),
        "1h":  timedelta(hours=1),
        "6h":  timedelta(hours=6),
        "24h": timedelta(hours=24),
        "3d":  timedelta(days=3),
        "7d":  timedelta(days=7),
        "31d": timedelta(days=31),
        "91d": timedelta(days=91),
    }
    return mapping.get(choice, timedelta(hours=24))

def constant_time_check(user_input):
    return hmac.compare_digest(user_input.encode(), UPLOAD_PASSWORD)

def rate_limited(ip):
    now = time.time()
    attempts = failed_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < 300]
    failed_attempts[ip] = attempts
    return len(attempts) > 5

def record_failure(ip):
    failed_attempts.setdefault(ip, []).append(time.time())

# ================= ROUTES =================

@app.route("/")
def index():
    if SECURE_MODE and not session.get("authenticated"):
        return render_template_string(LOGIN_HTML)
    return render_template_string(INDEX_HTML, secure=SECURE_MODE)

@app.route("/auth", methods=["POST"])
def auth():
    ip = request.remote_addr

    if rate_limited(ip):
        return "Too many attempts. Try later.", 429

    password = request.form.get("password", "")
    if constant_time_check(password):
        session["authenticated"] = True
        return redirect("/")
    else:
        record_failure(ip)
        time.sleep(1)  # slow brute force
        return render_template_string(LOGIN_HTML, error="Wrong password")

@app.route("/upload", methods=["POST"])
def upload():
    if SECURE_MODE and not session.get("authenticated"):
        abort(403)

    if "file" not in request.files:
        return "No file", 400

    file = request.files["file"]

    if file.filename == "":
        return "Empty filename", 400

    if len(request.files) > 1:
        return "Only one file allowed", 400

    folder_uuid = str(uuid.uuid4())
    folder_path = os.path.join(UPLOAD_ROOT, folder_uuid)
    os.makedirs(folder_path)

    file_path = os.path.join(folder_path, file.filename)
    file.save(file_path)
    size = os.path.getsize(file_path)

    expiry_choice = request.form.get("expiry", "24h")
    expiry = datetime.utcnow() + expiration_from_choice(expiry_choice)

    password = request.form.get("password")
    password = password if password else None

    meta = {
        "filename": file.filename,
        "size": size,
        "expiry": expiry.isoformat(),
        "password": password
    }

    with open(os.path.join(folder_path, "meta.json"), "w") as f:
        json.dump(meta, f)

    short_word = generate_short_word()
    short_links[short_word] = folder_uuid

    # ---- Telemetry ----
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "unknown")
    log_upload(
        ip=ip,
        user_agent=user_agent,
        filename=file.filename,
        size_bytes=size,
        expiry_choice=expiry_choice,
        expiry_datetime=expiry,
        folder_uuid=folder_uuid,
        short_word=short_word,
        password_protected=bool(password),
    )
    # -------------------

    return jsonify({
        "short_url": request.host_url + short_word,
        "direct_url": request.host_url + "direct/" + folder_uuid,
        "filename": file.filename,
        "size": size,
        "expiry_seconds": int((expiry - datetime.utcnow()).total_seconds())
    })

@app.route("/<word>")
def short_download(word):
    if word not in short_links:
        abort(404)
    return redirect(url_for("download_page", folder_uuid=short_links[word]))

@app.route("/file/<folder_uuid>", methods=["GET", "POST"])
def download_page(folder_uuid):
    folder_path = os.path.join(UPLOAD_ROOT, folder_uuid)
    meta_path = os.path.join(folder_path, "meta.json")

    if not os.path.exists(meta_path):
        abort(404)

    with open(meta_path) as f:
        meta = json.load(f)

    expiry = datetime.fromisoformat(meta["expiry"])
    remaining_seconds = max(0, int((expiry - datetime.utcnow()).total_seconds()))

    if meta["password"]:
        if request.method == "POST":
            if request.form.get("password") != meta["password"]:
                return render_template_string(DOWNLOAD_HTML, meta=meta, error="Wrong password", remaining_seconds=remaining_seconds)
        else:
            return render_template_string(DOWNLOAD_HTML, meta=meta, locked=True, remaining_seconds=remaining_seconds)

    return render_template_string(DOWNLOAD_HTML, meta=meta, download=True, uuid=folder_uuid, remaining_seconds=remaining_seconds)

@app.route("/direct/<folder_uuid>")
def direct_download(folder_uuid):
    folder_path = os.path.join(UPLOAD_ROOT, folder_uuid)
    meta_path = os.path.join(folder_path, "meta.json")
    if not os.path.exists(meta_path):
        abort(404)

    with open(meta_path) as f:
        meta = json.load(f)

    file_path = os.path.join(folder_path, meta["filename"])
    increment_download_count(folder_uuid)
    return send_file(file_path, as_attachment=True)

@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(e):
    return jsonify({"error": "File exceeds the 4 GB maximum size limit."}), 413

# ================= HTML =================

LOGIN_HTML = """
<!doctype html>
<html data-bs-theme="dark">
<head>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-light">
<div class="container py-5" style="max-width:400px;">
<h2>Vorodrop - drop.voronet.net</h2>
<br>
<h5>To prevent abuse, only authenticated users can upload files over the internet.</h5>
<h6>If you do not know the password, or want significantly faster upload/download speeds, use drop.internal.voronet.net in the voronet network.</h6>
<br>
<br>
<form method="post" action="/auth">
<input type="password" name="password" class="form-control mb-3" placeholder="Enter Password">
<button class="btn btn-primary w-100">Enter</button>
</form>
{% if error %}
<div class="alert alert-danger mt-3">{{ error }}</div>
{% endif %}
</div>
</body>
<footer class="mt-5 py-4 border-top border-secondary text-secondary" style="font-size: 0.8rem;">
  <div class="container">
    <div class="row">
      <div class="col-md-6 mb-3">
        <strong class="text-light">vorodrop</strong> &mdash; Internal file sharing for voronet.net<br>
        drop.voronet.net &bull; Not for public use
      </div>
      <div class="col-md-6 mb-3 text-md-end">
        Max file size: 4 GB &bull; Files auto-expire after upload &bull; Download speeds may vary
      </div>
    </div>

    <div class="alert alert-warning py-2 px-3" style="font-size: 0.78rem;">
      <strong>&#9888; Security Notice:</strong>
      Files uploaded to this service are <strong>not encrypted</strong> at rest or in transit unless your connection uses HTTPS.
      File-level passwords protect the download page only &mdash; they do not encrypt the file itself.
      Anyone with access to this server or network may be able to view uploaded files regardless of whether a password is set.
      <strong>Do not upload sensitive, confidential, or personally identifiable information.</strong>
    </div>

    <div class="alert alert-danger py-2 px-3 mt-2" style="font-size: 0.78rem;">
      <strong>&#9888; Download Warning:</strong>
      This service does not scan, verify, or guarantee the safety of any uploaded files.
      Files may contain malware, viruses, or other harmful content.
      vorodrop and voronet.net accept no responsibility for any damage caused by files downloaded from this service.
      Hosting or distributing illegal content via this service is strictly prohibited.
      <strong>Only download files if the link was sent to you directly by someone you know and trust.</strong>
    </div>

    <div class="text-secondary mt-2" style="font-size: 0.75rem;">
      Files are stored temporarily and deleted automatically upon expiry. No guarantee is made regarding availability or integrity of stored files.
      This service is provided as-is with no warranties expressed or implied.
      By uploading or downloading files, you accept sole responsibility for the content and any consequences of its use.
    </div>
  </div>
</footer>
</html>
"""

internal_version_disclaimer = "- INTERNAL VERSION (drop.internal.voronet.net)" if SECURE_MODE else ""

INDEX_HTML = """
<!doctype html>
<html data-bs-theme="dark">
<head>
<meta charset="utf-8">
<title>Vorodrop - File Sharing %%DISCLAIMER%%</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-light">
<div class="container py-5">
<h2>Vorodrop File Upload</h2>
<form id="uploadForm">
<div class="mb-3">
<input class="form-control" type="file" name="file" required>
</div>
<br>
<h6>Choose the amount of time to exist</h6>
<div class="mb-3">
<select class="form-select" name="expiry">
<option value="1m">1 Minute</option>
<option value="5m">5 Minutes</option>
<option value="1h">1 Hour</option>
<option value="6h">6 Hours</option>
<option value="24h" selected>24 Hours</option>
<option value="3d">3 Days</option>
<option value="7d">1 Week</option>
<option value="31d">1 Month</option>
<option value="91d">1 Semester</option>
</select>
</div>
<br>
<h6>Enter an optional password for downloading from a browser</h6>
<div class="mb-3">
  <div class="input-group">
    <input class="form-control" type="password" name="password" id="passwordField" placeholder="Optional File Password">
    <button class="btn btn-outline-secondary" type="button" id="togglePassword" tabindex="-1">
      <svg id="eyeIcon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
        <path d="M16 8s-3-5.5-8-5.5S0 8 0 8s3 5.5 8 5.5S16 8 16 8zM1.173 8a13.133 13.133 0 0 1 1.66-2.043C4.12 4.668 5.88 3.5 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.133 13.133 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755C11.879 11.332 10.119 12.5 8 12.5c-2.12 0-3.879-1.168-5.168-2.457A13.134 13.134 0 0 1 1.172 8z"/>
        <path d="M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM4.5 8a3.5 3.5 0 1 1 7 0 3.5 3.5 0 0 1-7 0z"/>
      </svg>
    </button>
  </div>
</div>
<br>
<button class="btn btn-primary">Upload</button>
</form>

<div class="progress mt-4" style="height: 25px; display:none;">
<div class="progress-bar" role="progressbar" style="width: 0%">0%</div>
</div>
<div id="speed" class="mt-2"></div>
<div id="result" class="mt-4">Large files may take a moment to process after uploading reaches 100%</div>
</div>

<script>

document.getElementById("togglePassword").addEventListener("click", function() {
  const field = document.getElementById("passwordField");
  const icon = document.getElementById("eyeIcon");
  const isPassword = field.type === "password";
  field.type = isPassword ? "text" : "password";
  icon.innerHTML = isPassword
    ? `<path d="M13.359 11.238C15.06 9.72 16 8 16 8s-3-5.5-8-5.5a7.028 7.028 0 0 0-2.79.588l.77.771A5.944 5.944 0 0 1 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.134 13.134 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755-.165.165-.337.328-.517.486l.708.709z"/><path d="M11.297 9.176a3.5 3.5 0 0 0-4.474-4.474l.823.823a2.5 2.5 0 0 1 2.829 2.829l.822.822zm-2.943 1.299.822.822a3.5 3.5 0 0 1-4.474-4.474l.823.823a2.5 2.5 0 0 0 2.829 2.829z"/><path d="M3.35 5.47c-.18.16-.353.322-.518.487A13.134 13.134 0 0 0 1.172 8l.195.288c.335.48.83 1.12 1.465 1.755C4.121 11.332 5.881 12.5 8 12.5c.716 0 1.39-.133 2.02-.36l.77.772A7.029 7.029 0 0 1 8 13.5C3 13.5 0 8 0 8s.939-1.721 2.641-3.238l.708.709z"/><path fill-rule="evenodd" d="M13.646 14.354l-12-12 .708-.708 12 12-.708.708z"/>`
    : `<path d="M16 8s-3-5.5-8-5.5S0 8 0 8s3 5.5 8 5.5S16 8 16 8zM1.173 8a13.133 13.133 0 0 1 1.66-2.043C4.12 4.668 5.88 3.5 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.133 13.133 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755C11.879 11.332 10.119 12.5 8 12.5c-2.12 0-3.879-1.168-5.168-2.457A13.134 13.134 0 0 1 1.172 8z"/><path d="M8 5.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zM4.5 8a3.5 3.5 0 1 1 7 0 3.5 3.5 0 0 1-7 0z"/>`;
});


const form = document.getElementById("uploadForm");
form.addEventListener("submit", function(e) {
  e.preventDefault();

  const fileInput = form.querySelector('input[type="file"]');
  const maxSize = 4 * 1024 * 1024 * 1024;
  if (fileInput.files[0] && fileInput.files[0].size > maxSize) {
    document.getElementById("result").innerHTML =
      `<div class="alert alert-danger">File is too large. Maximum size is 4 GB.</div>`;
    return;
  }
const data = new FormData(form);
const xhr = new XMLHttpRequest();
xhr.open("POST", "/upload", true);

let startTime = Date.now();
document.querySelector(".progress").style.display = "block";

xhr.upload.onprogress = function(e) {
if (e.lengthComputable) {
let percent = (e.loaded / e.total) * 100;
let elapsed = (Date.now() - startTime) / 1000;
let speed = (e.loaded / 1024 / 1024 / elapsed).toFixed(2);
document.querySelector(".progress-bar").style.width = percent + "%";
document.querySelector(".progress-bar").innerText = percent.toFixed(1) + "%";
document.getElementById("speed").innerText = speed + " MB/s";
}
};

xhr.onload = function() {
  if (xhr.status === 200) {
    let res = JSON.parse(xhr.responseText);
    let remaining = res.expiry_seconds;

    document.getElementById("result").innerHTML =
      `<div class="alert alert-success">
        Short URL: <a href="${res.short_url}" class="text-info">${res.short_url}</a><br>
        Direct URL (wget): <code>${res.direct_url}</code><br>
        Filename: ${res.filename}<br>
        Size: ${(res.size/1024/1024).toFixed(2)} MB<br>
        Expires in: <span id="countdown"></span>
      </div>`;

    function formatTime(s) {
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      return h > 0
        ? `${h}h ${m}m ${sec}s`
        : `${m}m ${sec}s`;
    }

    document.getElementById("countdown").innerText = formatTime(remaining);

const timer = setInterval(function() {
  remaining--;
  const el = document.getElementById("countdown");
  if (!el) {
    clearInterval(timer);
    return;
  }
  if (remaining <= 0) {
    clearInterval(timer);
    el.innerText = "Expired";
  } else {
    el.innerText = formatTime(remaining);
  }
}, 1000);
  } else if (xhr.status === 413) {
    document.querySelector(".progress").style.display = "none";
    document.getElementById("result").innerHTML =
      `<div class="alert alert-danger">File is too large. Maximum size is 4 GB.</div>`;
  } else {
    document.querySelector(".progress").style.display = "none";
    document.getElementById("result").innerHTML =
      `<div class="alert alert-danger">Upload failed (HTTP ${xhr.status}).</div>`;
  }

};

xhr.send(data);
});
</script>
</body>
<footer class="mt-5 py-4 border-top border-secondary text-secondary" style="font-size: 0.8rem;">
  <div class="container">
    <div class="row">
      <div class="col-md-6 mb-3">
        <strong class="text-light">vorodrop</strong> &mdash; Internal file sharing for voronet.net<br>
        drop.voronet.net &bull; Not for public use
      </div>
      <div class="col-md-6 mb-3 text-md-end">
        Max file size: 4 GB &bull; Files auto-expire after upload &bull; Download speeds may vary
      </div>
    </div>

    <div class="alert alert-warning py-2 px-3" style="font-size: 0.78rem;">
      <strong>&#9888; Security Notice:</strong>
      Files uploaded to this service are <strong>not encrypted</strong> at rest or in transit unless your connection uses HTTPS.
      File-level passwords protect the download page only &mdash; they do not encrypt the file itself.
      Anyone with access to this server or network may be able to view uploaded files regardless of whether a password is set.
      <strong>Do not upload sensitive, confidential, or personally identifiable information.</strong>
    </div>

    <div class="alert alert-danger py-2 px-3 mt-2" style="font-size: 0.78rem;">
      <strong>&#9888; Download Warning:</strong>
      This service does not scan, verify, or guarantee the safety of any uploaded files.
      Files may contain malware, viruses, or other harmful content.
      vorodrop and voronet.net accept no responsibility for any damage caused by files downloaded from this service.
      Hosting or distributing illegal content via this service is strictly prohibited.
      <strong>Only download files if the link was sent to you directly by someone you know and trust.</strong>
    </div>

    <div class="text-secondary mt-2" style="font-size: 0.75rem;">
      Files are stored temporarily and deleted automatically upon expiry. No guarantee is made regarding availability or integrity of stored files.
      This service is provided as-is with no warranties expressed or implied.
      By uploading or downloading files, you accept sole responsibility for the content and any consequences of its use.
    </div>
  </div>
</footer>
</html>
""".replace("%%DISCLAIMER%%", internal_version_disclaimer)

DOWNLOAD_HTML = """
<!doctype html>
<html data-bs-theme="dark">
<head>
<meta charset="utf-8">
<title>Download %%DISCLAIMER%%</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-light">
<div class="container py-5">
<h3>{{ meta.filename }}</h3>
<p>Size: {{ (meta.size/1024/1024)|round(2) }} MB</p>
<p>Expires in: <span id="countdown"></span></p>
{% if locked %}
<form method="post">
<input type="password" name="password" class="form-control mb-3" placeholder="Password">
<button class="btn btn-primary">Unlock</button>
</form>
{% elif download %}
<a href="/direct/{{ uuid }}" class="btn btn-success">Download</a>
{% endif %}

{% if error %}
<div class="alert alert-danger mt-3">{{ error }}</div>
{% endif %}
</div>

<script>
  let remaining = {{ remaining_seconds }};

  function formatTime(s) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    return h > 0 ? `${h}h ${m}m ${sec}s` : `${m}m ${sec}s`;
  }

  document.getElementById("countdown").innerText = formatTime(remaining);

  const timer = setInterval(function() {
    remaining--;
    if (remaining <= 0) {
      clearInterval(timer);
      document.getElementById("countdown").innerText = "Expired";
    } else {
      document.getElementById("countdown").innerText = formatTime(remaining);
    }
  }, 1000);
</script>

</body>

<footer class="mt-5 py-4 border-top border-secondary text-secondary" style="font-size: 0.8rem;">
  <div class="container">
    <div class="row">
      <div class="col-md-6 mb-3">
        <strong class="text-light">vorodrop</strong> &mdash; Internal file sharing for voronet.net<br>
        drop.voronet.net &bull; Not for public use
      </div>
      <div class="col-md-6 mb-3 text-md-end">
        Max file size: 4 GB &bull; Files auto-expire after upload &bull; Download speeds may vary
      </div>
    </div>

    <div class="alert alert-warning py-2 px-3" style="font-size: 0.78rem;">
      <strong>&#9888; Security Notice:</strong>
      Files uploaded to this service are <strong>not encrypted</strong> at rest or in transit unless your connection uses HTTPS.
      File-level passwords protect the download page only &mdash; they do not encrypt the file itself.
      Anyone with access to this server or network may be able to view uploaded files regardless of whether a password is set.
      <strong>Do not upload sensitive, confidential, or personally identifiable information.</strong>
    </div>

    <div class="alert alert-danger py-2 px-3 mt-2" style="font-size: 0.78rem;">
      <strong>&#9888; Download Warning:</strong>
      This service does not scan, verify, or guarantee the safety of any uploaded files.
      Files may contain malware, viruses, or other harmful content.
      vorodrop and voronet.net accept no responsibility for any damage caused by files downloaded from this service.
      Hosting or distributing illegal content via this service is strictly prohibited.
      <strong>Only download files if the link was sent to you directly by someone you know and trust.</strong>
    </div>

    <div class="text-secondary mt-2" style="font-size: 0.75rem;">
      Files are stored temporarily and deleted automatically upon expiry. No guarantee is made regarding availability or integrity of stored files.
      This service is provided as-is with no warranties expressed or implied.
      By uploading or downloading files, you accept sole responsibility for the content and any consequences of its use.
    </div>
  </div>
</footer>
</html>
""".replace("%%DISCLAIMER%%", internal_version_disclaimer)


# ================= RUN =================

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=80, debug=False)

#production
if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=80)