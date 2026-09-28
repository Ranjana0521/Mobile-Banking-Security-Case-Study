import os, sqlite3, secrets, hashlib, hmac, base64, json, time
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_SECRET = os.environ.get("APP_SECRET", "dev-only-change-this-secret")
# For a classroom demo only. Generate a persistent key and store it securely in production.
_raw_key = os.environ.get("AES_KEY")
if _raw_key:
    AES_KEY = base64.urlsafe_b64decode(_raw_key)
else:
    AES_KEY = hashlib.sha256(b"classroom-demo-key-change-me").digest()

app = Flask(__name__)
app.secret_key = APP_SECRET
DB = os.environ.get("BANK_DB", "bank_demo.db")

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            salt BLOB NOT NULL, password_hash BLOB NOT NULL, balance REAL NOT NULL DEFAULT 5000)""")
        con.execute("""CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, encrypted_record BLOB NOT NULL,
            created_at TEXT NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL)""")

def derive_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

def encrypt_record(payload):
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(AES_KEY).encrypt(nonce, json.dumps(payload).encode(), None)
    return nonce + ciphertext

def decrypt_record(blob):
    return json.loads(AESGCM(AES_KEY).decrypt(blob[:12], blob[12:], None).decode())

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

PAGE = """
<!doctype html><html><head><title>SecureBank Demo</title>
<style>
body{font-family:Arial,sans-serif;background:#f3f7fc;margin:0;color:#182b49}
header{background:#123c73;color:white;padding:18px 7%;font-size:22px;font-weight:bold}
main{max-width:760px;margin:28px auto;background:white;padding:28px;border-radius:14px;box-shadow:0 6px 22px #1c355515}
input,button{padding:11px;margin:7px 0;border:1px solid #cbd5e1;border-radius:7px;font-size:15px}
button{background:#1769aa;color:white;border:0;cursor:pointer}
a{color:#1769aa} .msg{background:#e9f6ed;padding:10px;border-radius:7px;margin:8px 0}
small{color:#61728b} .row{display:flex;gap:12px;flex-wrap:wrap}
</style></head><body><header>🔐 SecureBank — Security Demo</header><main>
{% with messages=get_flashed_messages() %}{% for m in messages %}<div class="msg">{{m}}</div>{% endfor %}{% endwith %}
{{body|safe}}
</main></body></html>
"""

def page(body, **ctx):
    return render_template_string(PAGE, body=render_template_string(body, **ctx))

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return page("""<h1>Mobile Banking Security Prototype</h1>
    <p>Demonstrates password hashing, AES-GCM encrypted transaction records, OTP confirmation, and simple risk checks.</p>
    <p><a href="/register">Create demo account</a> · <a href="/login">Log in</a></p>
    <small>Demo only — do not enter real banking credentials or use real money.</small>""")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
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
    return page("""<h1>Create account</h1><form method="post">
    <input name="username" placeholder="Username" required minlength="3"><br>
    <input name="password" type="password" placeholder="Password (8+ characters)" required minlength="8"><br>
    <button>Create account</button></form><a href="/login">Already registered? Log in</a>""")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        with db() as con:
            user=con.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        if user and hmac.compare_digest(derive_password(password, user["salt"]), user["password_hash"]):
            session.clear()
            session["user_id"]=user["id"]
            session["username"]=user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return page("""<h1>Log in</h1><form method="post">
    <input name="username" placeholder="Username" required><br>
    <input name="password" type="password" placeholder="Password" required><br>
    <button>Log in</button></form><a href="/register">Create an account</a>""")

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
            history.append(f'<li>{rec["time"]}: ₹{rec["amount"]:.2f} to {rec["recipient"]} — {r["status"]}</li>')
        except Exception:
            history.append("<li>Encrypted transaction record (unable to decrypt)</li>")
    return page("""<h1>Welcome, {{username}}</h1>
    <h2>Available demo balance: ₹{{"%.2f"|format(balance)}}</h2>
    <h3>Make a transfer</h3><form method="post" action="/transfer">
    <input name="recipient" placeholder="Recipient / account alias" required><br>
    <input name="amount" type="number" min="1" step="0.01" placeholder="Amount in ₹" required><br>
    <button>Continue securely</button></form>
    <h3>Recent transactions</h3><ul>{{history|safe}}</ul>
    <p><a href="/logout">Log out</a></p><small>Prototype controls only. OTP is simulated and printed in the server terminal.</small>""",
    username=session["username"], balance=user["balance"], history="".join(history))

@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    recipient=request.form.get("recipient","").strip()
    try: amount=round(float(request.form.get("amount","0")),2)
    except ValueError: amount=0
    if not recipient or amount <= 0:
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
    session["pending"]={"recipient":recipient,"amount":amount,"otp":otp,"expires":time.time()+180}
    print(f"[DEMO OTP] User {session['username']}: {otp} (valid 3 minutes)")
    flash("Demo OTP generated. Check the server terminal, then enter it below.")
    return page("""<h1>Verify transfer</h1><p>Transfer ₹{{amount}} to <b>{{recipient}}</b></p>
    <form method="post" action="/confirm"><input name="otp" placeholder="6-digit OTP" required maxlength="6">
    <button>Verify and transfer</button></form><a href="/dashboard">Cancel</a>""",
    amount=amount, recipient=recipient)

@app.route("/confirm", methods=["POST"])
@login_required
def confirm():
    pending=session.get("pending")
    otp=request.form.get("otp","")
    if not pending or time.time()>pending.get("expires",0):
        session.pop("pending",None)
        flash("OTP expired. Start the transfer again.")
        return redirect(url_for("dashboard"))
    if not hmac.compare_digest(otp, pending["otp"]):
        flash("Incorrect OTP.")
        return redirect(url_for("dashboard"))
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        user=con.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
        if not user or user["balance"] < pending["amount"]:
            con.rollback()
            flash("Transfer cancelled: balance changed or insufficient.")
            return redirect(url_for("dashboard"))
        new_balance=round(user["balance"]-pending["amount"],2)
        now=datetime.now(timezone.utc).isoformat(timespec="seconds")
        record={"recipient":pending["recipient"],"amount":pending["amount"],"time":now}
        con.execute("UPDATE users SET balance=? WHERE id=?",(new_balance,session["user_id"]))
        con.execute("INSERT INTO transactions(user_id,encrypted_record,created_at,amount,status) VALUES(?,?,?,?,?)",
                    (session["user_id"],encrypt_record(record),now,pending["amount"],"COMPLETED"))
        con.commit()
    session.pop("pending",None)
    flash("Transfer completed in the demo. Transaction details are encrypted at rest.")
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
