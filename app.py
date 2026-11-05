"""Cloud-Based Cybersecurity Log Monitoring and Alert System (Flask + Azure Cosmos DB)."""
import json
import logging
import os
import secrets
import smtplib
import threading
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("security")

# Optional Application Insights. Must run BEFORE Flask is imported so requests are auto-instrumented.
if os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
    from azure.monitor.opentelemetry import configure_azure_monitor
    configure_azure_monitor()

from flask import Flask, Response, redirect, render_template, request, session, url_for  # noqa: E402
from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: E402
from werkzeug.security import check_password_hash, generate_password_hash  # noqa: E402

FAIL_THRESHOLD = int(os.getenv("FAIL_THRESHOLD", 5))   # project setting, not a security standard
WINDOW_MINUTES = int(os.getenv("WINDOW_MINUTES", 5))
DB_NAME = "cybersecurity_demo"


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="milliseconds")   # fixed format, so string comparison = time comparison


# ---------------------------------------------------------------- storage ---
class CosmosStore:
    label = "Azure Cosmos DB"
    is_cloud = True

    def __init__(self, endpoint, key=None):
        from azure.cosmos import CosmosClient, PartitionKey
        if key:                                     # account key: can create the database/containers itself
            self.auth = "account key"
            db = CosmosClient(endpoint, credential=key).create_database_if_not_exists(DB_NAME)
            pk = PartitionKey(path="/source")
            self.logs = db.create_container_if_not_exists(id="security_logs", partition_key=pk)
            self.alerts = db.create_container_if_not_exists(id="security_alerts", partition_key=pk)
        else:                                       # managed identity (App Service) or `az login` (local)
            from azure.identity import DefaultAzureCredential
            self.auth = "managed identity"
            db = CosmosClient(endpoint, credential=DefaultAzureCredential()).get_database_client(DB_NAME)
            self.logs = db.get_container_client("security_logs")       # must already exist (see README)
            self.alerts = db.get_container_client("security_alerts")

    @staticmethod
    def _q(container, query, params=None, source=None):
        opts = {"partition_key": source} if source else {"enable_cross_partition_query": True}
        return list(container.query_items(query=query, parameters=params or [], **opts))

    def add_event(self, e):
        self.logs.create_item(e)

    def add_alert(self, a):
        self.alerts.create_item(a)

    def recent_events(self, limit=10):
        return self._q(self.logs, f"SELECT * FROM c ORDER BY c.timestamp DESC OFFSET 0 LIMIT {int(limit)}")

    def events_since(self, since):
        return self._q(self.logs, "SELECT c.timestamp, c.status FROM c WHERE c.timestamp >= @t",
                       [{"name": "@t", "value": since}])

    def failed_since(self, source, since):
        q = "SELECT VALUE COUNT(1) FROM c WHERE c.status = 'Failed' AND c.timestamp >= @t"
        return sum(self._q(self.logs, q, [{"name": "@t", "value": since}], source))

    def has_open_alert(self, source, since):
        q = "SELECT VALUE COUNT(1) FROM c WHERE c.status = 'Open' AND c.created_at >= @t"
        return sum(self._q(self.alerts, q, [{"name": "@t", "value": since}], source)) > 0

    def counts(self):
        count = lambda c, where="": sum(self._q(c, f"SELECT VALUE COUNT(1) FROM c {where}"))
        total = count(self.logs)
        failed = count(self.logs, "WHERE c.status = 'Failed'")
        return {"total": total, "success": total - failed, "failed": failed,
                "alerts": count(self.alerts, "WHERE c.status = 'Open'")}

    def list_alerts(self, limit=50):
        return self._q(self.alerts, f"SELECT * FROM c ORDER BY c.created_at DESC OFFSET 0 LIMIT {int(limit)}")

    def resolve_alert(self, alert_id, source):
        item = self.alerts.read_item(item=alert_id, partition_key=source)
        item["status"] = "Resolved"
        self.alerts.replace_item(item=item, body=item)


class LocalStore:
    """In-memory fallback so the app can be rehearsed without Azure. Data is lost on restart."""
    label = "Local demo (in-memory)"
    is_cloud = False

    def __init__(self):
        self.events, self.alerts, self.lock = [], [], threading.Lock()

    def add_event(self, e):
        with self.lock:
            self.events.append(e)

    def add_alert(self, a):
        with self.lock:
            self.alerts.append(a)

    def recent_events(self, limit=10):
        return sorted(self.events, key=lambda e: e["timestamp"], reverse=True)[:limit]

    def events_since(self, since):
        return [e for e in self.events if e["timestamp"] >= since]

    def failed_since(self, source, since):
        return sum(1 for e in self.events
                   if e["source"] == source and e["status"] == "Failed" and e["timestamp"] >= since)

    def has_open_alert(self, source, since):
        return any(a["source"] == source and a["status"] == "Open" and a["created_at"] >= since
                   for a in self.alerts)

    def counts(self):
        failed = sum(1 for e in self.events if e["status"] == "Failed")
        return {"total": len(self.events), "success": len(self.events) - failed, "failed": failed,
                "alerts": sum(1 for a in self.alerts if a["status"] == "Open")}

    def list_alerts(self, limit=50):
        return sorted(self.alerts, key=lambda a: a["created_at"], reverse=True)[:limit]

    def resolve_alert(self, alert_id, source):
        for a in self.alerts:
            if a["id"] == alert_id:
                a["status"] = "Resolved"


endpoint, key = os.getenv("COSMOS_ENDPOINT"), os.getenv("COSMOS_KEY")
if endpoint:                                        # no key = managed identity / az login
    store = CosmosStore(endpoint, key)
    log.info("Storage: Azure Cosmos DB (%s)", store.auth)
else:
    store = LocalStore()
    print("[!] COSMOS_ENDPOINT not set - using in-memory storage (not Azure).")

# ------------------------------------------------------------------- auth ---
# Demo accounts for the login page; only password hashes are kept in memory.
USERS = {"admin": generate_password_hash("Admin@123"), "student": generate_password_hash("Student@123")}

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
_admin_pw = os.getenv("ADMIN_PASSWORD")
if not _admin_pw:
    _admin_pw = secrets.token_urlsafe(9)
    print(f"[!] ADMIN_PASSWORD not set. Temporary dashboard password: {_admin_pw}")
ADMIN_HASH = generate_password_hash(_admin_pw)


def verify_credentials(username, password):
    """Accept the demo accounts and the ADMIN_USER / ADMIN_PASSWORD pair."""
    username, password = (username or "").strip(), password or ""
    if username in USERS and check_password_hash(USERS[username], password):
        return True
    return username == ADMIN_USER and check_password_hash(ADMIN_HASH, password)


def safe_next(target):
    """Only allow redirects back to a local path (no open redirects)."""
    if not target or not target.startswith("/") or target.startswith("//"):
        return False
    if any(ch in target for ch in "\\\r\n\t"):
        return False
    parsed = urlparse(target)
    return not parsed.scheme and not parsed.netloc


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session.get("user"):
            return view(*args, **kwargs)

        nxt = request.path if request.method == "GET" else request.referrer or "/"
        if not safe_next(nxt):
            nxt = "/"

        # Support HTTP Basic auth for API/script access.
        # NEVER send a WWW-Authenticate challenge — that triggers the browser's
        # native popup and hides the Flask login page entirely.
        auth = request.authorization
        if auth and verify_credentials(auth.username, auth.password or ""):
            return view(*args, **kwargs)

        # Always redirect to Flask login page (browsers and API clients alike).
        return redirect(url_for("login", next=nxt))
    return wrapper


# ---------------------------------------------------------- notifications ---
def _send_webhook(alert):                           # e.g. an Azure Logic App HTTP trigger
    url = os.getenv("ALERT_WEBHOOK_URL", "")
    if url.startswith("https://"):
        req = urllib.request.Request(url, data=json.dumps(alert).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).close()


def _send_email(alert):                             # plain SMTP (e.g. Gmail with an app password)
    host, to = os.getenv("SMTP_HOST"), os.getenv("ALERT_EMAIL_TO")
    if not (host and to):
        return
    msg = EmailMessage()
    msg["Subject"] = f"[Security alert] {alert['failed_attempts']} failed logins detected"
    msg["From"] = os.getenv("SMTP_FROM") or os.getenv("SMTP_USER", "alerts@localhost")
    msg["To"] = to
    msg.set_content(f"{alert['message']}\nSeverity: {alert['severity']}\nTime (UTC): {alert['created_at']}\n\n"
                    "Review it on the dashboard. This is a rule-based alert and may be a false positive.")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", 587)), timeout=15) as smtp:
        smtp.starttls()
        if os.getenv("SMTP_USER"):
            smtp.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
        smtp.send_message(msg)


def notify(alert):
    """Optional alert delivery, run off the request thread so logins are never slowed or broken by it."""
    def run():
        for send in (_send_webhook, _send_email):
            try:
                send(alert)
            except Exception as exc:
                log.warning("alert notification failed (%s): %s", send.__name__, exc)
    threading.Thread(target=run, daemon=True).start()


# -------------------------------------------------------------- detection ---
def record_login(username, password, source):
    ok = verify_credentials(username, password)
    status = "Success" if ok else "Failed"
    store.add_event({"id": str(uuid.uuid4()), "timestamp": iso(now()), "username": username[:50] or "(blank)",
                     "status": status, "source": source})   # never log the password
    log.info("login_event status=%s user=%r source=%r", status, username[:50], source)
    if not ok:
        check_rule(source)
    return ok


def check_rule(source):
    """Alert when FAIL_THRESHOLD failures from one source fall inside the rolling window."""
    since = iso(now() - timedelta(minutes=WINDOW_MINUTES))
    failures = store.failed_since(source, since)
    if failures >= FAIL_THRESHOLD and not store.has_open_alert(source, since):   # no duplicate alerts
        alert = {"id": str(uuid.uuid4()), "type": "Suspicious Activity", "severity": "High",
                 "source": source, "failed_attempts": failures, "status": "Open", "created_at": iso(now()),
                 "message": f"{failures} failed attempts from {source} within {WINDOW_MINUTES} minutes"}
        store.add_alert(alert)
        log.warning("security_alert type=%s source=%r failed_attempts=%d", alert["type"], source, failures)
        notify(alert)


def parse_ts(value):
    """Turn an ISO string (or a datetime from the SDK) into an aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def build_timeline(minutes=60, bucket=5):
    """Successful/failed login counts per time bucket (UTC) for the dashboard chart."""
    start = now() - timedelta(minutes=minutes)
    n = minutes // bucket
    out = {"labels": [(start + timedelta(minutes=bucket * i)).strftime("%H:%M") for i in range(n)],
           "success": [0] * n, "failed": [0] * n}
    for e in store.events_since(iso(start)):
        i = int((parse_ts(e["timestamp"]) - start).total_seconds() // (bucket * 60))
        out["success" if e["status"] == "Success" else "failed"][max(0, min(n - 1, i))] += 1
    return out


# -------------------------------------------------------------------- app ---
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)   # sessions reset on restart unless SECRET_KEY is set
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.getenv("WEBSITE_SITE_NAME")),     # HTTPS on App Service
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
if os.getenv("WEBSITE_SITE_NAME"):                      # set by Azure App Service: trust its proxy header
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)


def client_ip():
    ip = request.remote_addr or "unknown"
    return ip.rsplit(":", 1)[0] if ip.count(":") == 1 else ip   # App Service may append a port


@app.template_filter("ts")
def fmt_ts(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if not value:
        return ""
    return str(value)[:19].replace("T", " ")


@app.context_processor
def inject():
    return {"store": store, "threshold": FAIL_THRESHOLD, "window": WINDOW_MINUTES,
            "current_user": session.get("user")}


@app.route("/")
@admin_required
def dashboard():
    return render_template("dashboard.html", page="dashboard", c=store.counts(),
                           events=store.recent_events(8), alerts=store.list_alerts(4),
                           timeline=build_timeline())


@app.route("/logs")
@admin_required
def logs():
    return render_template("logs.html", page="logs", events=store.recent_events(100))


@app.route("/alerts")
@admin_required
def alerts():
    return render_template("alerts.html", page="alerts", alerts=store.list_alerts(100))


@app.post("/alerts/<alert_id>/resolve")
@admin_required
def resolve(alert_id):
    source = request.form.get("source")
    if source:
        store.resolve_alert(alert_id, source)
    return redirect(url_for("alerts"))


@app.route("/login", methods=["GET", "POST"])     # signs you in AND records the attempt as a demo event
def login():
    next_url = request.values.get("next", "")
    result = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        ok = record_login(username, request.form.get("password", ""), client_ip())
        if ok:
            session.clear()                       # new session ID on login (session fixation)
            session["user"] = username
            session.permanent = True
            return redirect(next_url if safe_next(next_url) else url_for("dashboard"))
        result = "fail"
    return render_template("login.html", page="login", result=result, next=next_url)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.post("/simulate")                              # dashboard buttons for demo traffic
@admin_required
def simulate():
    source = (request.form.get("source") or "203.0.113.7").strip()[:45]
    action = request.form.get("action")
    if action == "success":
        record_login("admin", "Admin@123", source)
    elif action == "fail":
        record_login("admin", "wrong-password", source)
    elif action == "burst":
        for _ in range(FAIL_THRESHOLD):
            record_login("admin", "wrong-password", source)
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
