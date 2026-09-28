import os, sqlite3, secrets, hashlib, hmac, base64, json, time
import math
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_ENV = os.environ.get("APP_ENV", "development")
IS_PRODUCTION = APP_ENV == "production"

def load_secrets():
    if IS_PRODUCTION:
        values = {"APP_SECRET": os.environ.get("APP_SECRET"), "AES_KEY": os.environ.get("AES_KEY")}
    else:
        secret_path = os.path.join(os.path.dirname(__file__), ".local_secrets.json")
        try:
            with open(secret_path, encoding="utf-8") as secret_file:
                values = json.load(secret_file)
        except FileNotFoundError:
            values = {
                "APP_SECRET": secrets.token_urlsafe(48),
                "AES_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
            }
            try:
                with open(secret_path, "x", encoding="utf-8") as secret_file:
                    json.dump(values, secret_file)
                try:
                    os.chmod(secret_path, 0o600)
                except OSError:
                    pass
            except FileExistsError:
                with open(secret_path, encoding="utf-8") as secret_file:
                    values = json.load(secret_file)

    app_secret = values.get("APP_SECRET")
    encoded_key = values.get("AES_KEY")
    if not app_secret or len(app_secret.encode("utf-8")) < 32:
        raise RuntimeError("APP_SECRET must contain at least 32 bytes")
    if not encoded_key:
        raise RuntimeError("AES_KEY must be configured")
    try:
        aes_key = base64.b64decode(encoded_key.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("AES_KEY must be URL-safe base64") from exc
    if len(aes_key) != 32:
        raise RuntimeError("AES_KEY must decode to exactly 32 bytes")
    return app_secret, aes_key

APP_SECRET, AES_KEY = load_secrets()
OTP_HASH_KEY = hmac.new(APP_SECRET.encode("utf-8"), b"securebank-demo-otp-hmac-v1", hashlib.sha256).digest()
LEGACY_DEMO_AES_KEY = hashlib.sha256(b"classroom-demo-key-change-me").digest()

app = Flask(__name__)
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)
DB = os.environ.get("BANK_DB", "bank_demo.db")

@contextmanager
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

def init_db():
    with db() as con:
        con.execute("PRAGMA secure_delete=ON")
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            salt BLOB NOT NULL, password_hash BLOB NOT NULL, balance REAL NOT NULL DEFAULT 5000)""")
        con.execute("""CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, encrypted_record BLOB NOT NULL,
            status TEXT NOT NULL)""")
        columns = {row[1] for row in con.execute("PRAGMA table_info(transactions)")}
        migrated_plaintext = False
        legacy_columns = columns.intersection({"amount", "created_at"})
        if legacy_columns:
            selected_columns = ["id", "encrypted_record", *sorted(legacy_columns)]
            query = "SELECT " + ",".join(selected_columns) + " FROM transactions"
            for row in con.execute(query).fetchall():
                record = None
                for key in dict.fromkeys((AES_KEY, LEGACY_DEMO_AES_KEY)):
                    try:
                        record = json.loads(AESGCM(key).decrypt(
                            row["encrypted_record"][:12], row["encrypted_record"][12:], None
                        ).decode())
                        break
                    except Exception:
                        continue
                if record is None:
                    raise RuntimeError(
                        "Could not decrypt an existing transaction during migration. "
                        "Set the original AES_KEY before retrying."
                    )
                if "amount" in legacy_columns:
                    record.setdefault("amount", row["amount"])
                if "created_at" in legacy_columns:
                    record.setdefault("time", row["created_at"])
                nonce = secrets.token_bytes(12)
                encrypted = nonce + AESGCM(AES_KEY).encrypt(
                    nonce, json.dumps(record).encode(), None
                )
                con.execute(
                    "UPDATE transactions SET encrypted_record=? WHERE id=?",
                    (encrypted, row["id"]),
                )
        if "amount" in columns:
            con.execute("ALTER TABLE transactions DROP COLUMN amount")
            migrated_plaintext = True
        if "created_at" in columns:
            con.execute("ALTER TABLE transactions DROP COLUMN created_at")
            migrated_plaintext = True
        con.execute("""CREATE TABLE IF NOT EXISTS pending_transfers(
            user_id INTEGER PRIMARY KEY, encrypted_details BLOB NOT NULL,
            otp_salt BLOB NOT NULL, otp_hash BLOB NOT NULL, expires_at REAL NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0)""")
    if migrated_plaintext:
        with db() as con:
            con.execute("VACUUM")

def derive_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

def encrypt_record(payload):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(AES_KEY).encrypt(nonce, json.dumps(payload).encode(), None)
    return nonce + ciphertext

def decrypt_record(blob):
    return json.loads(AESGCM(AES_KEY).decrypt(blob[:12], blob[12:], None).decode())

def csrf_token():
    return session.setdefault("_csrf_token", secrets.token_urlsafe(32))

def valid_csrf_token():
    expected = session.get("_csrf_token", "")
    provided = request.form.get("csrf_token", "")
    return bool(expected and provided) and hmac.compare_digest(expected, provided)

def hash_otp(otp, salt):
    return hmac.new(OTP_HASH_KEY, salt + otp.encode("ascii", errors="ignore"), hashlib.sha256).digest()

app.jinja_env.globals["csrf_token"] = csrf_token

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureBank | Digital Banking</title>
<style>
:root{color-scheme:light;--ink:#17251f;--muted:#69756f;--line:#e3e9e4;--paper:#fff;--canvas:#f4f6f2;--green:#174d3b;--green-dark:#103c2d;--lime:#d9efad;--mint:#eaf3e9;--amber:#bc7a2a;--red:#a9473d;--shadow:0 18px 50px #1c32220d}
*{box-sizing:border-box}
body{margin:0;background:var(--canvas);color:var(--ink);font-family:Inter,"Segoe UI",sans-serif;font-size:15px;line-height:1.55}
a{color:var(--green);text-decoration:none}a:hover{text-decoration:underline}
.topbar{height:72px;background:var(--paper);border-bottom:1px solid var(--line);display:flex;align-items:center}
.topbar-inner{width:min(1160px,calc(100% - 48px));margin:auto;display:flex;align-items:center;justify-content:space-between;gap:24px}
.brand{display:flex;align-items:center;gap:11px;color:var(--ink);font-weight:750;letter-spacing:.01em;font-size:17px}
.brand-mark{width:34px;height:34px;border-radius:10px;background:var(--green);display:grid;place-items:center;color:var(--lime);font-size:18px}
.brand small{display:block;color:var(--muted);font-size:9px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;line-height:1.2}
.nav{display:flex;align-items:center;gap:28px;color:var(--muted);font-size:13px;font-weight:600}
.nav a{color:inherit}.nav .active{color:var(--green)}
.user-nav{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:13px}
.logout-form{margin:0}.logout-button{border:0;padding:0;background:none;color:var(--green);font:inherit;font-size:13px;cursor:pointer}
.avatar{width:34px;height:34px;border-radius:50%;background:var(--mint);display:grid;place-items:center;color:var(--green);font-weight:750;text-transform:uppercase}
main{width:min(1160px,calc(100% - 48px));margin:36px auto 64px}
.flash-list{display:grid;gap:8px;margin:0 0 20px}
.msg{padding:12px 15px;border:1px solid #cfe1cf;border-radius:8px;background:#f0f7ed;color:#315e3e;font-size:14px}
.success-dialog{width:min(430px,calc(100% - 32px));padding:32px;border:1px solid var(--line);border-radius:12px;background:var(--paper);color:var(--ink);text-align:center;box-shadow:0 24px 80px #10281d40}.success-dialog::backdrop{background:#12251dc7;backdrop-filter:blur(3px)}.success-mark{width:56px;height:56px;margin:0 auto 17px;border-radius:50%;display:grid;place-items:center;background:var(--mint);color:var(--green);font-size:27px;font-weight:800}.success-dialog h2{margin:5px 0 9px;font-size:23px}.success-dialog p:not(.eyebrow){color:var(--muted);font-size:14px;margin-bottom:23px}.success-dialog .eyebrow{margin:0}
.page-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;margin:0 0 24px}
.eyebrow{margin:0 0 5px;color:var(--green);font-size:11px;font-weight:750;letter-spacing:.14em;text-transform:uppercase}
h1,h2,h3,p{margin-top:0}h1{font-size:30px;line-height:1.2;letter-spacing:-.025em;margin-bottom:7px}h2{font-size:20px;line-height:1.3;margin-bottom:8px}h3{font-size:15px;margin-bottom:14px}
.subtle{color:var(--muted);margin-bottom:0;font-size:14px}
.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(290px,.85fr);gap:20px;align-items:start}
.main-stack,.side-stack{display:grid;gap:20px;min-width:0}
.balance-card{position:relative;overflow:hidden;min-height:225px;padding:28px 30px;border-radius:12px;background:var(--green);color:white;box-shadow:var(--shadow)}
.balance-card:after{content:"";position:absolute;width:220px;height:220px;right:-28px;top:-24px;transform:rotate(25deg);background:repeating-linear-gradient(0deg,transparent 0 17px,#ffffff12 17px 18px),repeating-linear-gradient(90deg,transparent 0 17px,#ffffff12 17px 18px)}
.balance-top,.balance-bottom{position:relative;z-index:1;display:flex;justify-content:space-between;align-items:center;gap:16px}
.balance-label{font-size:13px;color:#d5e4dc}.balance-amount{font-size:38px;line-height:1.2;letter-spacing:-.03em;font-weight:700;margin:12px 0 24px}
.account-tag{padding:6px 10px;border:1px solid #ffffff40;border-radius:5px;font-size:10px;letter-spacing:.11em;font-weight:700;text-transform:uppercase}
.account-number{font-size:12px;color:#d5e4dc;letter-spacing:.14em}.balance-bottom{border-top:1px solid #ffffff30;padding-top:15px;font-size:12px;color:#d5e4dc}
.panel{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:22px 23px;box-shadow:var(--shadow)}
.panel-heading{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px}.panel-heading h2,.panel-heading h3{margin:0}
.activity-list{list-style:none;margin:0;padding:0}.activity-item{display:grid;grid-template-columns:38px minmax(0,1fr) auto;gap:12px;align-items:center;padding:14px 0;border-top:1px solid #edf0ed}.activity-icon{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;background:#f2f4ef;color:var(--green);font-size:17px}.activity-copy{min-width:0}.activity-copy strong{display:block;overflow-wrap:anywhere;font-size:13px;font-weight:650}.activity-copy small{display:block;color:var(--muted);font-size:11px;margin-top:2px}.activity-amount{text-align:right;font-size:13px;font-weight:700;white-space:nowrap}.status{display:inline-flex;align-items:center;gap:5px;color:#46754e;font-size:10px;font-weight:700;margin-top:3px}.status:before{content:"";width:6px;height:6px;border-radius:50%;background:#6eaa64}
.empty-state{padding:30px 12px;text-align:center;color:var(--muted);font-size:13px}.empty-icon{width:42px;height:42px;border-radius:50%;background:var(--mint);display:grid;place-items:center;color:var(--green);font-size:20px;margin:0 auto 12px}
.field{margin:0 0 15px}.field label{display:block;margin-bottom:6px;font-size:12px;font-weight:650;color:#3f4c45}.field input{display:block;width:100%;height:44px;border:1px solid #d7dfd8;border-radius:6px;padding:0 12px;background:#fff;color:var(--ink);font:inherit;font-size:14px;outline:none;transition:border-color .15s,box-shadow .15s}.field input:focus{border-color:#5d8a70;box-shadow:0 0 0 3px #174d3b16}.field input::placeholder{color:#9ba49e}
.button{min-height:44px;display:inline-flex;align-items:center;justify-content:center;gap:8px;border:0;border-radius:6px;padding:0 16px;background:var(--green);color:white;font:inherit;font-weight:650;font-size:13px;cursor:pointer;transition:background .15s,transform .15s}.button:hover{background:var(--green-dark);transform:translateY(-1px);text-decoration:none}.button.full{width:100%}.button.secondary{background:white;color:var(--green);border:1px solid #cbd9ce}.button.secondary:hover{background:var(--mint)}
.transfer-note,.security-copy{color:var(--muted);font-size:11px;line-height:1.5;margin:13px 0 0}.security-row{display:flex;align-items:flex-start;gap:12px}.security-symbol{width:34px;height:34px;flex:none;display:grid;place-items:center;background:var(--mint);border-radius:50%;color:var(--green);font-weight:800}.security-row strong{font-size:13px}.security-copy{margin:3px 0 0}
.auth-layout{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(340px,.9fr);min-height:500px;border-radius:12px;overflow:hidden;background:white;border:1px solid var(--line);box-shadow:var(--shadow)}
.auth-intro{position:relative;overflow:hidden;background:var(--green);color:white;padding:58px 54px;display:flex;flex-direction:column;justify-content:space-between}.auth-intro:after{content:"";position:absolute;width:220px;height:250px;right:-18px;bottom:-28px;transform:rotate(25deg);background:repeating-linear-gradient(0deg,transparent 0 19px,#ffffff10 19px 20px),repeating-linear-gradient(90deg,transparent 0 19px,#ffffff10 19px 20px)}.auth-intro>*{position:relative;z-index:1}.auth-intro .eyebrow{color:var(--lime)}.auth-intro h1{font-size:38px;max-width:440px;margin:18px 0 14px}.auth-intro p{max-width:410px;color:#d5e4dc;font-size:15px}.trust-line{font-size:12px;color:#d5e4dc;padding-top:24px;border-top:1px solid #ffffff30}
.auth-form{align-self:center;padding:48px clamp(28px,6vw,70px)}.auth-form h2{font-size:24px;margin-bottom:7px}.auth-form .subtle{margin-bottom:25px}.auth-form form{margin-bottom:18px}.auth-form .field{margin-bottom:17px}.auth-links{font-size:13px;color:var(--muted)}
.otp-summary{background:var(--canvas);border:1px solid var(--line);border-radius:7px;padding:14px 16px;margin:20px 0;font-size:14px}.otp-summary strong{display:block;margin-top:3px}.demo-label{font-size:10px;font-weight:750;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.footer{display:flex;justify-content:space-between;gap:20px;border-top:1px solid var(--line);padding-top:18px;margin-top:28px;color:var(--muted);font-size:11px}
@media(max-width:800px){.nav{display:none}.dashboard-grid{grid-template-columns:1fr}.side-stack{grid-row:1}.balance-amount{font-size:34px}.auth-layout{grid-template-columns:1fr}.auth-intro{padding:36px 32px;min-height:280px}.auth-intro h1{font-size:32px}.auth-form{padding:34px 32px}}
@media(max-width:520px){.topbar{height:62px}.topbar-inner,main{width:calc(100% - 28px)}main{margin:24px auto 40px}.user-name{display:none}.page-heading{align-items:flex-start;flex-direction:column}.page-heading h1{font-size:26px}.balance-card{padding:22px;min-height:210px}.balance-amount{font-size:32px;margin:10px 0 20px}.panel{padding:19px 17px}.auth-intro{padding:30px 24px;min-height:255px}.auth-intro h1{font-size:29px}.auth-form{padding:30px 24px}.footer{flex-direction:column;gap:5px}}
</style>
</head>
<body>
<header class="topbar"><div class="topbar-inner">
    <a class="brand" href="{{ url_for('home') }}"><span class="brand-mark">S</span><span>SecureBank<small>Digital banking</small></span></a>
    {% if session.get('user_id') %}<nav class="nav"><a class="active" href="{{ url_for('dashboard') }}">Overview</a><span>Security</span></nav><div class="user-nav"><span class="avatar">{{ session.get('username', 'U')[:1] }}</span><span class="user-name">{{ session.get('username') }}</span><form class="logout-form" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="logout-button" type="submit">Log out</button></form></div>{% else %}<span class="demo-label">Secure demo environment</span>{% endif %}
</div></header>
<main>
{% with messages=get_flashed_messages(with_categories=true) %}{% if messages %}<div class="flash-list">{% for category,m in messages %}{% if category == 'transfer_success' %}<dialog class="success-dialog" id="transfer-success" aria-labelledby="transfer-success-title"><span class="success-mark" aria-hidden="true">✓</span><p class="eyebrow">SecureBank · Demo transfer</p><h2 id="transfer-success-title">Transfer successful</h2><p>{{m}}</p><button class="button full" type="button" data-close-success>Continue</button></dialog><script>const notice=document.getElementById("transfer-success");if(notice){notice.showModal();notice.querySelector("[data-close-success]").addEventListener("click",()=>notice.close())}</script>{% else %}<div class="msg">{{m}}</div>{% endif %}{% endfor %}</div>{% endif %}{% endwith %}
{{body|safe}}
<footer class="footer"><span>SecureBank Demo · Educational prototype</span><span>Never enter real credentials or financial information</span></footer>
</main>
</body>
</html>
"""

def page(body, **ctx):
    return render_template_string(PAGE, body=render_template_string(body, **ctx))

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return page("""<section class="auth-layout">
    <div class="auth-intro"><div><p class="eyebrow">SecureBank · Demo access</p><h1>Banking, with security built in.</h1>
    <p>Explore a mobile banking security prototype with protected sign-in, encrypted transaction records, and transfer verification.</p></div>
    <div class="trust-line">Password protection <span aria-hidden="true">·</span> Encrypted records <span aria-hidden="true">·</span> Verified transfers</div></div>
    <div class="auth-form"><p class="eyebrow">Welcome</p><h2>Your demo account</h2>
    <p class="subtle">Sign in to continue, or create an account to explore the dashboard.</p>
    <a class="button full" href="{{ url_for('login') }}">Log in securely <span aria-hidden="true">→</span></a>
    <p class="auth-links" style="margin-top:17px">New to SecureBank? <a href="{{ url_for('register') }}">Create demo account</a></p>
    <div class="security-row" style="margin-top:28px"><span class="security-symbol">✓</span><div><strong>Demo environment</strong><p class="security-copy">Uses simulated funds and OTP verification. Do not enter real banking details.</p></div></div>
    </div></section>""")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.")
            return redirect(url_for("register"))
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if len(username) < 3 or len(password) < 8:
            flash("Username must be at least 3 characters and password at least 8.")
        else:
            salt = secrets.token_bytes(16)
            ph = derive_password(password, salt)
            try:
                with db() as con:
                    con.execute("INSERT INTO users(username,salt,password_hash,balance) VALUES(?,?,?,?)",
                                (username,salt,ph,5000.0))
                flash("Account created. Starting demo balance: ₹5,000.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username already exists.")
    return page("""<section class="auth-layout"><div class="auth-intro"><div><p class="eyebrow">SecureBank · New account</p><h1>A safer way to explore digital banking.</h1>
    <p>Your demo account starts with ₹5,000 in simulated funds. Credentials are protected with salted password hashing.</p></div><div class="trust-line">Secure sign-up · Simulated balance · No real funds</div></div>
    <div class="auth-form"><p class="eyebrow">Get started</p><h2>Create demo account</h2><p class="subtle">Choose a username and a password of at least 8 characters.</p>
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><div class="field"><label for="username">Username</label><input id="username" name="username" placeholder="Choose a username" required minlength="3" autocomplete="username"></div>
    <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" placeholder="At least 8 characters" required minlength="8" autocomplete="new-password"></div>
    <button class="button full" type="submit">Create account</button></form><p class="auth-links">Already registered? <a href="{{ url_for('login') }}">Log in</a></p>
    </div></section>""")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Your form expired. Please try again.")
            return redirect(url_for("login"))
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        with db() as con:
            user=con.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if user and hmac.compare_digest(derive_password(password, user["salt"]), user["password_hash"]):
            session.clear()
            session.permanent=True
            session["user_id"]=user["id"]
            session["username"]=user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return page("""<section class="auth-layout"><div class="auth-intro"><div><p class="eyebrow">SecureBank · Private access</p><h1>Your account, thoughtfully protected.</h1>
    <p>Sign in to review your demo balance, manage a transfer, and see your encrypted transaction history.</p></div><div class="trust-line">Salted password hashing · Secure session · Transfer checks</div></div>
    <div class="auth-form"><p class="eyebrow">Good to see you</p><h2>Log in</h2><p class="subtle">Enter your demo account details to continue.</p>
    <form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><div class="field"><label for="username">Username</label><input id="username" name="username" placeholder="Your username" required autocomplete="username"></div>
    <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" placeholder="Your password" required autocomplete="current-password"></div>
    <button class="button full" type="submit">Log in securely</button></form><p class="auth-links">Need an account? <a href="{{ url_for('register') }}">Create demo account</a></p>
    </div></section>""")

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as con:
        user=con.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
        rows=con.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 10",(session["user_id"],)).fetchall()
    history=[]
    for r in rows:
        try:
            rec=decrypt_record(r["encrypted_record"])
            history.append({"time":rec["time"],"amount":rec["amount"],"recipient":rec["recipient"],"status":r["status"]})
        except Exception:
            history.append({"time":"Transaction details protected","amount":None,"recipient":"Encrypted record","status":r["status"]})
    return page("""<div class="page-heading"><div><p class="eyebrow">Personal banking</p><h1>Good day, {{ username }}</h1><p class="subtle">Here is your account overview.</p></div><span class="demo-label">Demo account · INR</span></div>
            <div class="dashboard-grid"><div class="main-stack">
            <section class="balance-card"><div class="balance-top"><span class="balance-label">Available balance</span><span class="account-tag">Everyday account</span></div>
            <div class="balance-amount">₹{{ "{:,.2f}".format(balance) }}</div><div class="balance-bottom"><span class="account-number">•••• &nbsp;•••• &nbsp;•••• &nbsp;2048</span><span>Updated just now</span></div></section>
            <section class="panel"><div class="panel-heading"><div><p class="eyebrow">Account activity</p><h2>Recent transactions</h2></div><span class="demo-label">Latest 10</span></div>
            {% if history %}<ul class="activity-list">{% for item in history %}<li class="activity-item"><span class="activity-icon" aria-hidden="true">↗</span><div class="activity-copy"><strong>{{ item.recipient }}</strong><small>{{ item.time }}</small><span class="status">{{ item.status|title }}</span></div><span class="activity-amount">{% if item.amount is not none %}−₹{{ "{:,.2f}".format(item.amount) }}{% else %}Protected{% endif %}</span></li>{% endfor %}</ul>
            {% else %}<div class="empty-state"><span class="empty-icon" aria-hidden="true">↗</span><strong>No activity yet</strong><br>Your completed transfers will appear here.</div>{% endif %}</section>
            <section class="panel"><div class="security-row"><span class="security-symbol">✓</span><div><strong>Security is active</strong><p class="security-copy">Transaction details are encrypted at rest. Transfers are checked before confirmation.</p></div></div></section>
            </div><aside class="side-stack"><section class="panel"><div class="panel-heading"><div><p class="eyebrow">Payments</p><h2>Make a transfer</h2></div></div>
            <form method="post" action="{{ url_for('transfer') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><div class="field"><label for="recipient">Recipient</label><input id="recipient" name="recipient" placeholder="Name or account alias" required autocomplete="off"></div>
            <div class="field"><label for="amount">Amount</label><input id="amount" name="amount" type="number" min="1" step="0.01" placeholder="0.00" required></div>
            <button class="button full" type="submit">Review transfer <span aria-hidden="true">→</span></button></form>
            <p class="transfer-note">A one-time verification code is required to complete an eligible transfer. Simulated funds only.</p></section>
            <section class="panel"><p class="eyebrow">Account details</p><h3>Protected by design</h3><div class="security-row"><span class="security-symbol">✓</span><div><strong>Encrypted records</strong><p class="security-copy">Transaction details are protected using authenticated encryption.</p></div></div></section>
            </aside></div>""", username=session["username"], balance=user["balance"], history=history)

@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    if not valid_csrf_token():
        flash("Your form expired. Please try again.")
        return redirect(url_for("dashboard"))
    recipient=request.form.get("recipient","").strip()
    try: amount=round(float(request.form.get("amount","0")),2)
    except ValueError: amount=0
    if not recipient or not math.isfinite(amount) or amount <= 0:
        flash("Enter a valid recipient and amount.")
        return redirect(url_for("dashboard"))
    with db() as con:
        user=con.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    if amount > user["balance"]:
        flash("Transfer blocked: insufficient balance.")
        return redirect(url_for("dashboard"))
    # Basic educational risk rule: large transfer or high fraction of available balance.
    if amount >= 2000 or amount > user["balance"] * 0.6:
        flash("Transfer flagged for additional review due to the demo risk rule.")
        return redirect(url_for("dashboard"))
    otp=f"{secrets.randbelow(1000000):06d}"
    salt=secrets.token_bytes(16)
    otp_hash=hash_otp(otp, salt)
    expires_at=time.time()+180
    encrypted_details=encrypt_record({"recipient":recipient,"amount":amount})
    with db() as con:
        con.execute("""INSERT INTO pending_transfers(
            user_id,encrypted_details,otp_salt,otp_hash,expires_at,attempts)
            VALUES(?,?,?,?,?,0)
            ON CONFLICT(user_id) DO UPDATE SET encrypted_details=excluded.encrypted_details,
            otp_salt=excluded.otp_salt,otp_hash=excluded.otp_hash,
            expires_at=excluded.expires_at,attempts=0""",
            (session["user_id"],encrypted_details,salt,otp_hash,expires_at))
    print(f"[DEMO OTP] User {session['username']}: {otp} (valid 3 minutes)")
    if not IS_PRODUCTION:
        flash("Local demo code: " + otp + ". It expires in 3 minutes.")
    else:
        flash("Demo OTP generated. Check the server logs. It expires in 3 minutes.")
    return page("""<section class="auth-layout"><div class="auth-intro"><div><p class="eyebrow">SecureBank · Transfer security</p><h1>One more step to keep your money safe.</h1>
    <p>Confirm this transfer with the one-time code displayed in the server terminal. The code expires after three minutes.</p></div><div class="trust-line">Recipient and amount are held for verification</div></div>
    <div class="auth-form"><p class="eyebrow">Review and verify</p><h2>Confirm transfer</h2><p class="subtle">Check the details before completing your transfer.</p>
    <div class="otp-summary"><span class="demo-label">Sending to</span><strong>{{ recipient }}</strong><span class="demo-label" style="display:block;margin-top:14px">Transfer amount</span><strong>₹{{ "{:,.2f}".format(amount) }}</strong></div>
    <form method="post" action="{{ url_for('confirm') }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><div class="field"><label for="otp">6-digit verification code</label><input id="otp" name="otp" inputmode="numeric" autocomplete="one-time-code" placeholder="Enter code" required maxlength="6" pattern="[0-9]{6}"></div>
    <button class="button full" type="submit">Verify and transfer</button></form><a class="button secondary full" href="{{ url_for('dashboard') }}">Cancel transfer</a>
    </div></section>""",
    amount=amount, recipient=recipient)

@app.route("/confirm", methods=["POST"])
@login_required
def confirm():
    if not valid_csrf_token():
        flash("Your form expired. Please start the transfer again.")
        return redirect(url_for("dashboard"))
    otp=request.form.get("otp","")
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        pending=con.execute("SELECT * FROM pending_transfers WHERE user_id=?",(session["user_id"],)).fetchone()
        if not pending or time.time()>pending["expires_at"]:
            con.execute("DELETE FROM pending_transfers WHERE user_id=?",(session["user_id"],))
            con.commit()
            flash("OTP expired. Start the transfer again.")
            return redirect(url_for("dashboard"))
        if pending["attempts"] >= 5:
            con.execute("DELETE FROM pending_transfers WHERE user_id=?",(session["user_id"],))
            con.commit()
            flash("Too many incorrect codes. Start the transfer again.")
            return redirect(url_for("dashboard"))
        submitted_hash=hash_otp(otp,pending["otp_salt"])
        otp_is_valid=len(otp)==6 and otp.isascii() and otp.isdigit() and hmac.compare_digest(submitted_hash,pending["otp_hash"])
        if not otp_is_valid:
            attempts=pending["attempts"]+1
            if attempts >= 5:
                con.execute("DELETE FROM pending_transfers WHERE user_id=?",(session["user_id"],))
                message="Too many incorrect codes. Start the transfer again."
            else:
                con.execute("UPDATE pending_transfers SET attempts=? WHERE user_id=?",(attempts,session["user_id"]))
                message="Incorrect code. Try again or restart the transfer."
            con.commit()
            flash(message)
            return redirect(url_for("dashboard"))
        details=decrypt_record(pending["encrypted_details"])
        user=con.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
        if not user or user["balance"] < details["amount"]:
            con.execute("DELETE FROM pending_transfers WHERE user_id=?",(session["user_id"],))
            con.commit()
            flash("Transfer cancelled: balance changed or insufficient.")
            return redirect(url_for("dashboard"))
        new_balance=round(user["balance"]-details["amount"],2)
        now=datetime.now(timezone.utc).isoformat(timespec="seconds")
        record={"recipient":details["recipient"],"amount":details["amount"],"time":now}
        con.execute("UPDATE users SET balance=? WHERE id=?",(new_balance,session["user_id"]))
        con.execute("INSERT INTO transactions(user_id,encrypted_record,status) VALUES(?,?,?)",
                    (session["user_id"],encrypt_record(record),"COMPLETED"))
        con.execute("DELETE FROM pending_transfers WHERE user_id=?",(session["user_id"],))
        con.commit()
    flash("₹{:,.2f} sent to {}. Your demo balance has been updated.".format(details["amount"],details["recipient"]),"transfer_success")
    return redirect(url_for("dashboard"))

@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf_token():
        flash("Your form expired. Please try again.")
        return redirect(url_for("home"))
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
