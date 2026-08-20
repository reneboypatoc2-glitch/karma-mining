from flask import Flask, render_template, render_template_string, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, secrets, random, time, hashlib
from functools import wraps
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = BASE / "karma.db"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Wheel segments from the agreed design.
SEGMENTS = [1]*21 + [5]*13 + [10]*7 + [15]*4 + [20]*4 + [30]*2 + [50]*2 + [200]*1

# Rare multiplier pool.
MULTIPLIERS = [
    (1, 9000),
    (2, 700),
    (3, 200),
    (5, 70),
    (10, 20),
    (15, 7),
    (25, 2),
    (50, 1)
]


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()

    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        karma REAL NOT NULL DEFAULT 0,
        katching REAL NOT NULL DEFAULT 0,
        referral_code TEXT UNIQUE NOT NULL,
        referred_by INTEGER,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS deposits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        reference TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        confirmed_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS mining (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        deposit_id INTEGER NOT NULL,
        total_karma REAL NOT NULL,
        start_at INTEGER NOT NULL,
        end_at INTEGER NOT NULL,
        credited REAL NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        currency TEXT NOT NULL,
        amount REAL NOT NULL,
        kind TEXT NOT NULL,
        note TEXT,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS spins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        currency TEXT NOT NULL,
        bet REAL NOT NULL,
        chosen INTEGER NOT NULL,
        result INTEGER NOT NULL,
        multiplier REAL NOT NULL,
        win REAL NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    );
    """)

    # Create a local admin account for first-run testing.
    if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        con.execute(
            "INSERT INTO users(username,password_hash,referral_code,is_admin,created_at) VALUES(?,?,?,?,?)",
            (
                "admin",
                generate_password_hash("ChangeMe123!"),
                "ADMIN",
                1,
                int(time.time())
            )
        )

    con.commit()
    con.close()


def current_user():
    uid = session.get("uid")

    if not uid:
        return None

    con = db()
    user = con.execute(
        "SELECT * FROM users WHERE id=?",
        (uid,)
    ).fetchone()

    con.close()
    return user


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))

        return fn(*args, **kwargs)

    return wrapped


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        u = current_user()

        if not u or not u["is_admin"]:
            return redirect(url_for("login"))

        return fn(*args, **kwargs)

    return wrapped


def log_tx(con, uid, currency, amount, kind, note=""):
    con.execute(
        """
        INSERT INTO transactions
        (user_id,currency,amount,kind,note,created_at)
        VALUES(?,?,?,?,?,?)
        """,
        (
            uid,
            currency,
            amount,
            kind,
            note,
            int(time.time())
        )
    )


def apply_mining(con, uid):
    now = int(time.time())

    rows = con.execute(
        "SELECT * FROM mining WHERE user_id=? AND active=1",
        (uid,)
    ).fetchall()

    for m in rows:
        duration = max(1, m["end_at"] - m["start_at"])
        elapsed = min(
            duration,
            max(0, now - m["start_at"])
        )

        target = m["total_karma"] * (elapsed / duration)
        delta = max(0, target - m["credited"])

        if delta > 0:
            con.execute(
                "UPDATE users SET karma=karma+? WHERE id=?",
                (delta, uid)
            )

            con.execute(
                "UPDATE mining SET credited=? WHERE id=?",
                (target, m["id"])
            )

            log_tx(
                con,
                uid,
                "Karma",
                delta,
                "mining",
                f"Mining deposit #{m['deposit_id']}"
            )

        if now >= m["end_at"]:
            con.execute(
                "UPDATE mining SET active=0 WHERE id=?",
                (m["id"],)
            )


@app.context_processor
def inject_user():
    u = current_user()
    return {"user": u}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ref = request.form.get("ref", "").strip()

        if len(username) < 3 or len(password) < 8:
            flash(
                "Username must be at least 3 characters and password at least 8 characters."
            )
            return redirect(url_for("register"))

        con = db()

        try:

            referred_by = None

            if ref:
                r = con.execute(
                    "SELECT id FROM users WHERE referral_code=?",
                    (ref,)
                ).fetchone()

                if r:
                    referred_by = r["id"]

            code = secrets.token_urlsafe(7)

            con.execute(
                """
                INSERT INTO users
                (username,password_hash,referral_code,referred_by,created_at)
                VALUES(?,?,?,?,?)
                """,
                (
                    username,
                    generate_password_hash(password),
                    code,
                    referred_by,
                    int(time.time())
                )
            )

            con.commit()

            flash("Account created. Please log in.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash("That username is already taken.")

        finally:

            con.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        con = db()

        u = con.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        con.close()

        if u and check_password_hash(
            u["password_hash"],
            password
        ):
            session["uid"] = u["id"]

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html")


# ============================================================
# FORGOT PASSWORD
# ============================================================

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    # Prototype: reset by username; the link is displayed on-screen.
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        con = db()
        user = con.execute(
            "SELECT id, username FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if not user:
            con.close()
            flash("If that username exists, a reset link has been created.")
            return redirect(url_for("forgot_password"))

        con.execute(
            "UPDATE password_resets SET used=1 WHERE user_id=? AND used=0",
            (user["id"],)
        )

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = int(time.time())
        expires = now + (30 * 60)

        con.execute(
            """
            INSERT INTO password_resets
            (user_id, token_hash, expires_at, used, created_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            (user["id"], token_hash, expires, now)
        )
        con.commit()
        con.close()

        reset_url = url_for("reset_password", token=token, _external=True)

        return render_template_string(
            """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Password Reset — KARMA</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
<header><a class="brand" href="{{ url_for('index') }}"><img src="{{ url_for('static', filename='logo.png') }}" onerror="this.style.display='none'"><span>KARMA</span></a></header>
<main><div class="form card">
<h2>Password Reset</h2>
<p>Your reset link has been created for this prototype.</p>
<p><a class="button" href="{{ reset_url }}">Reset Password</a></p>
<p><small>This link expires in 30 minutes and can only be used once.</small></p>
<p><a href="{{ url_for('login') }}">Back to Login</a></p>
</div></main>
</body></html>""",
            reset_url=reset_url
        )

    return render_template_string(
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forgot Password — KARMA</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
<header><a class="brand" href="{{ url_for('index') }}"><img src="{{ url_for('static', filename='logo.png') }}" onerror="this.style.display='none'"><span>KARMA</span></a></header>
<main><div class="form card">
<h2>Forgot Password</h2>
<p>Enter your username to create a password reset link.</p>
<form method="post">
<input type="text" name="username" placeholder="Username" required autocomplete="username">
<button type="submit">Create Reset Link</button>
</form>
<p><a href="{{ url_for('login') }}">Back to Login</a></p>
</div></main>
</body></html>"""
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    con = db()

    reset = con.execute(
        """
        SELECT * FROM password_resets
        WHERE token_hash=? AND used=0 AND expires_at>?
        ORDER BY id DESC LIMIT 1
        """,
        (token_hash, now)
    ).fetchone()

    if not reset:
        con.close()
        flash("This password reset link is invalid or has expired.")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 8:
            con.close()
            flash("Password must be at least 8 characters.")
            return redirect(url_for("reset_password", token=token))

        if password != confirm:
            con.close()
            flash("Passwords do not match.")
            return redirect(url_for("reset_password", token=token))

        con.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(password), reset["user_id"])
        )
        con.execute(
            "UPDATE password_resets SET used=1 WHERE id=?",
            (reset["id"],)
        )
        con.commit()
        con.close()

        flash("Password changed successfully. You can now log in.")
        return redirect(url_for("login"))

    con.close()

    return render_template_string(
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Set New Password — KARMA</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
<header><a class="brand" href="{{ url_for('index') }}"><img src="{{ url_for('static', filename='logo.png') }}" onerror="this.style.display='none'"><span>KARMA</span></a></header>
<main><div class="form card">
<h2>Set New Password</h2>
<form method="post">
<input type="password" name="password" placeholder="New Password" minlength="8" required autocomplete="new-password">
<input type="password" name="confirm_password" placeholder="Confirm New Password" minlength="8" required autocomplete="new-password">
<button type="submit">Change Password</button>
</form>
<p><a href="{{ url_for('login') }}">Back to Login</a></p>
</div></main>
</body></html>"""
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("index")
    )


@app.route("/dashboard")
@login_required
def dashboard():

    con = db()

    apply_mining(
        con,
        session["uid"]
    )

    con.commit()

    u = con.execute(
        "SELECT * FROM users WHERE id=?",
        (session["uid"],)
    ).fetchone()

    mining = con.execute(
        """
        SELECT *
        FROM mining
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 10
        """,
        (u["id"],)
    ).fetchall()

    tx = con.execute(
        """
        SELECT *
        FROM transactions
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 12
        """,
        (u["id"],)
    ).fetchall()

    con.close()

    return render_template(
        "dashboard.html",
        u=u,
        mining=mining,
        tx=tx
    )


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():

    if request.method == "POST":

        try:
            amount = float(
                request.form.get(
                    "amount",
                    "0"
                )
            )

        except ValueError:
            amount = 0

        reference = request.form.get(
            "reference",
            ""
        ).strip()

        if amount < 10:

            flash(
                "Minimum deposit request is PHP 10."
            )

            return redirect(
                url_for("deposit")
            )

        con = db()

        con.execute(
            """
            INSERT INTO deposits
            (user_id,amount,reference,created_at)
            VALUES(?,?,?,?)
            """,
            (
                session["uid"],
                amount,
                reference,
                int(time.time())
            )
        )

        con.commit()
        con.close()

        flash(
            "Deposit submitted for manual confirmation."
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "deposit.html"
    )


@app.route("/daily", methods=["POST"])
@login_required
def daily():

    con = db()

    last = con.execute(
        """
        SELECT created_at
        FROM transactions
        WHERE user_id=? AND kind='daily'
        """,
        (session["uid"],)
    ).fetchone()

    today = time.strftime(
        "%Y-%m-%d",
        time.localtime()
    )

    if last and time.strftime(
        "%Y-%m-%d",
        time.localtime(last["created_at"])
    ) == today:

        flash(
            "Daily Katching has already been claimed."
        )

    else:

        con.execute(
            "UPDATE users SET katching=katching+5 WHERE id=?",
            (session["uid"],)
        )

        log_tx(
            con,
            session["uid"],
            "Katching",
            5,
            "daily",
            "Daily reward"
        )

        con.commit()

        flash(
            "You received 5 Katching."
        )

    con.close()

    return redirect(
        url_for("dashboard")
    )


@app.route("/wheel", methods=["GET", "POST"])
@login_required
def wheel():

    message = None
    result = None

    con = db()

    apply_mining(
        con,
        session["uid"]
    )

    if request.method == "POST":

        currency = request.form.get(
            "currency"
        )

        try:

            bet = float(
                request.form.get(
                    "bet",
                    "0"
                )
            )

            chosen = int(
                request.form.get(
                    "chosen",
                    "0"
                )
            )

        except ValueError:

            bet = 0
            chosen = 0

        if (
            currency not in ("Karma", "Katching")
            or not (10 <= bet <= 10000)
            or chosen not in set(SEGMENTS)
        ):

            flash(
                "Invalid wheel selection."
            )

        else:

            u = con.execute(
                "SELECT * FROM users WHERE id=?",
                (session["uid"],)
            ).fetchone()

            balance = (
                u["karma"]
                if currency == "Karma"
                else u["katching"]
            )

            if balance < bet:

                flash(
                    f"Not enough {currency}."
                )

            else:

                # Cryptographically stronger random outcome.
                chosen_result = secrets.choice(
                    SEGMENTS
                )

                population = [
                    x
                    for x, w in MULTIPLIERS
                    for _ in range(w)
                ]

                multiplier = secrets.choice(
                    population
                )

                win = 0

                if chosen_result == chosen:

                    # Base 1:1 profit.
                    win = bet * multiplier

                    con.execute(
                        f"""
                        UPDATE users
                        SET {currency.lower()} =
                            {currency.lower()} - ? + ?
                        WHERE id=?
                        """,
                        (
                            bet,
                            bet + win,
                            session["uid"]
                        )
                    )

                    log_tx(
                        con,
                        session["uid"],
                        currency,
                        win,
                        "wheel_win",
                        f"{chosen_result} at {multiplier}x"
                    )

                else:

                    con.execute(
                        f"""
                        UPDATE users
                        SET {currency.lower()} =
                            {currency.lower()} - ?
                        WHERE id=?
                        """,
                        (
                            bet,
                            session["uid"]
                        )
                    )

                    log_tx(
                        con,
                        session["uid"],
                        currency,
                        -bet,
                        "wheel_loss",
                        f"Result {chosen_result}"
                    )

                con.execute(
                    """
                    INSERT INTO spins
                    (user_id,currency,bet,chosen,result,multiplier,win,created_at)
                    VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        session["uid"],
                        currency,
                        bet,
                        chosen,
                        chosen_result,
                        multiplier,
                        win,
                        int(time.time())
                    )
                )

                con.commit()

                result = {
                    "chosen": chosen,
                    "result": chosen_result,
                    "multiplier": multiplier,
                    "win": win
                }

    u = con.execute(
        "SELECT * FROM users WHERE id=?",
        (session["uid"],)
    ).fetchone()

    con.close()

    return render_template(
        "wheel.html",
        u=u,
        result=result
    )


@app.route("/admin")
@admin_required
def admin():

    con = db()

    deposits = con.execute(
        """
        SELECT d.*, u.username
        FROM deposits d
        JOIN users u ON u.id=d.user_id
        ORDER BY d.id DESC
        LIMIT 100
        """
    ).fetchall()

    users = con.execute(
        """
        SELECT id,username,karma,katching,created_at
        FROM users
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()

    con.close()

    return render_template(
        "admin.html",
        deposits=deposits,
        users=users
    )


@app.route(
    "/admin/deposit/<int:did>/confirm",
    methods=["POST"]
)
@admin_required
def confirm_deposit(did):

    con = db()

    d = con.execute(
        "SELECT * FROM deposits WHERE id=?",
        (did,)
    ).fetchone()

    if not d or d["status"] != "pending":

        flash(
            "Deposit is not pending."
        )

        con.close()

        return redirect(
            url_for("admin")
        )

    # Confirm deposit and create an 8-day mining session.
    amount = d["amount"]

    total_karma = amount * 5

    now = int(time.time())

    end = now + 8 * 24 * 60 * 60

    con.execute(
        """
        UPDATE deposits
        SET status='confirmed',
            confirmed_at=?
        WHERE id=?
        """,
        (
            now,
            did
        )
    )

    con.execute(
        """
        INSERT INTO mining
        (user_id,deposit_id,total_karma,start_at,end_at)
        VALUES(?,?,?,?,?)
        """,
        (
            d["user_id"],
            did,
            total_karma,
            now,
            end
        )
    )

    log_tx(
        con,
        d["user_id"],
        "PHP",
        amount,
        "deposit_confirmed",
        f"Deposit #{did}"
    )

    # Recurring referral reward.
    referrer = con.execute(
        "SELECT referred_by FROM users WHERE id=?",
        (d["user_id"],)
    ).fetchone()

    if (
        referrer
        and referrer["referred_by"]
        and amount >= 10
    ):

        reward = amount / 10

        con.execute(
            """
            UPDATE users
            SET katching=katching+?
            WHERE id=?
            """,
            (
                reward,
                referrer["referred_by"]
            )
        )

        log_tx(
            con,
            referrer["referred_by"],
            "Katching",
            reward,
            "referral",
            f"10% recurring referral reward from user #{d['user_id']}"
        )

    con.commit()

    con.close()

    flash(
        "Deposit confirmed and mining activated."
    )

    return redirect(
        url_for("admin")
    )


init_db()


if __name__ == "__main__":
    app.run(
        debug=True
    )
