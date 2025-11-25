import os
import random
import sqlite3
from flask import Flask, request, session, redirect, render_template

# ----------------------------------------------------
# SECRET WORDS – GLOBAL (NO REPEATS)
# ----------------------------------------------------
SECRET_WORDS = {
    1: "SQL",
    2: "IS",
    3: "A",
    4: "LOCK",
    5: "INJECTION",
    6: "IS THE KEY"
}

# Some helpers for detection / flavor
ADVANCED_SEARCH_INJECTIONS = [
    "and 1=2 union select id, username, password from users",
    "and 1=2 union select id, username, hex(password) from users",
    "and 1=2 union select id, username, password from users where role='admin'",
    "and 1=2 union select 1, name, sql from sqlite_master",
    "and 1=2 union select id, username, password from users --",
    "and 1=2 union select id, username, password from users #",
    "and 1=2 union select id, username, password from users /*",
    "and 1=2 union select 1,2,3",
    "and 1=2 union select 1,2,3,4",
    "and 1=2  union  select",
    "and 1=2 union  select",
    "AnD 1=2 UnIoN SeLeCt",
    "%25' and 1=2 union select",
    "%27 and 1=2 union select",
    "union select null,null,null",
    "union select 1,sqlite_version(),3",
    "union select name,sql,3 from sqlite_master",
]

ADVANCED_BLIND_INJECTIONS = [
    "and 1=1",
    "and 1=2",
    "and substr(password,1,1)=",
    "and length(password)=",
    "and ascii(substr(password,1,1))",
    "and (select count(*) from users)",
    "and username like",
]

ADVANCED_DEBUG_INJECTIONS = {
    "union select name from sqlite_master --": "The archive whispers table names…",
    "union select sql from sqlite_master --": "Ancient schema scrolls unfold…",
    "union select username from users --": "User identities spill from the void…",
    "union select username || ':' || password from users --": "Credentials echo from forgotten pages…",
    "union select password from users where role='admin' --": "The admin’s key glows faintly…",
    "union select hex(password) from users where role='admin' --": "Encrypted whispers rise from deep within…",
    "union select sqlite_version() --": "The Archive reveals its age…",
    "union select count(*) from users --": "You sense the number of souls stored here…",
}

# ----------------------------------------------------
# FLASK APP
# ----------------------------------------------------
app = Flask(__name__)
app.secret_key = "super-secret-ctf-key"

# ----------------------------------------------------
# DATABASE PATH — LOCAL vs RENDER DISK
# ----------------------------------------------------
import os

if os.environ.get("RENDER"):
    DB_PATH = "/var/data/database.db"
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DB_PATH = os.path.join(BASE_DIR, "database.db")



# ----------------------------------------------------
# DB Helper
# ----------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create and seed database on first run."""
    if os.path.exists(DB_PATH) and os.path.getsize(DB_PATH) > 100:
        return

    conn = get_db()
    cur = conn.cursor()

    print("Initializing new database...")

    cur.executescript(
        """
        -- USERS
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        );

        INSERT INTO users (username, password, role) VALUES
            ('player', 'player', 'user'),
            ('admin',  'supersecret', 'admin');

        -- PRODUCTS
        CREATE TABLE products (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            description TEXT,
            price       REAL NOT NULL
        );

        INSERT INTO products (name, description, price) VALUES
            ('Dark Florish Onepiece', 'A mysterious dress. Rumored to hide secrets.', 95.00),
            ('Baggy Shirt', 'Loose and comfortable.', 55.00),
            ('Cotton Off-White Shirt', 'Soft and clean.', 65.00),
            ('Crop Sweater', 'Cozy for late night CTF.', 50.00);

        -- CART
        CREATE TABLE cart (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            quantity   INTEGER NOT NULL DEFAULT 1
        );

        -- ORDERS
        CREATE TABLE orders (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT NOT NULL,
            total      REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE order_items (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id   INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity   INTEGER NOT NULL,
            price      REAL NOT NULL
        );

        -- LOGS
        CREATE TABLE injection_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT,
            ip         TEXT,
            endpoint   TEXT,
            payload    TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    conn.commit()
    conn.close()
    print("Database initialized and seeded.")

# ----------------------------------------------------
# Ensure DB exists even when running under gunicorn
# ----------------------------------------------------
def ensure_db_ready():
    try:
        init_db()
    except Exception as e:
        print("DB init failed:", e)

ensure_db_ready()

# ----------------------------------------------------
# NAVBAR
# ----------------------------------------------------
@app.context_processor
def inject_navbar_user():
    if "user" in session:
        username = session["user"]
        html = f"""
        <li class='nav-item me-3'><span class="nav-link">Hi, {username}</span></li>
        <li class='nav-item'><a class="nav-link" href="/logout">Logout</a></li>
        """
    else:
        html = """
        <li class='nav-item'><a class="nav-link" href="/login">Login</a></li>
        """
    return {"NAVBAR_USER": html}


# ----------------------------------------------------
# INJECTION LOGGER
# ----------------------------------------------------
def log_injection(payload, endpoint):
    try:
        conn = get_db()
        cur = conn.cursor()
        username = session.get("user", "guest")
        ip = request.remote_addr or "unknown"
        cur.execute(
            "INSERT INTO injection_logs (username, ip, endpoint, payload) VALUES (?, ?, ?, ?)",
            (username, ip, endpoint, payload),
        )
        conn.commit()
        conn.close()
    except:
        # We ignore logging errors for teaching/demo purposes
        pass


# ----------------------------------------------------
# SECRET WORD AWARDER (NO DUPLICATES)
# ----------------------------------------------------
def award_random_secret_word():
    """
    Awards a random UNIQUE secret word.
    Uses session['secret_word_ids'] (IDs) and session['secret_words_collected'] (text).
    Never repeats across the whole quest.
    """
    if "secret_word_ids" not in session:
        session["secret_word_ids"] = []
    if "secret_words_collected" not in session:
        session["secret_words_collected"] = []

    remaining = [i for i in SECRET_WORDS if i not in session["secret_word_ids"]]

    if not remaining:
        session["last_secret_word"] = None
        return None

    new_id = random.choice(remaining)
    new_word = SECRET_WORDS[new_id]

    session["secret_word_ids"].append(new_id)
    session["secret_words_collected"].append(new_word)
    session["last_secret_word"] = new_word

    return new_word


@app.route("/")
def intro():
    return render_template("intro.html")

# ----------------------------------------------------
# HOME
# ----------------------------------------------------
@app.route("/home")
def index():
    return render_template("index.html", title="SQL Injection Quest – Home")


# ----------------------------------------------------
# LOGIN (LEVEL 1)
# ----------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", title="Login")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    injection_signs = ["'", "\"", ";", "--", "/*", "*/", " or ", " OR ", "union", "UNION", "select", "SELECT", "="]

    lower_user = username.lower()
    lower_pass = password.lower()

    is_injection = any(sig in lower_user or sig in lower_pass for sig in injection_signs)

    print("Injection detected?", is_injection, "USERNAME:", username, "PASSWORD:", password)


    conn = get_db()
    cur = conn.cursor()

    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    log_injection(f"{username} | {password}", "/login")

    try:
        cur.execute(query)
        row = cur.fetchone()
    except Exception as e:
        conn.close()
        return render_template(
            "login.html",
            title="Login",
            error=f"SQL error triggered: {e}",
        )

    conn.close()

    # CASE 1: Injection path → start quest + award first word (random, no repeat)
    if is_injection:
        award_random_secret_word()
        session["user"] = "player"
        session["role"] = "user"
        return redirect("/clue1")

    # CASE 2: Normal successful login (no injection) → boring user portal
    if row:
        session["user"] = row["username"]
        session["role"] = row["role"]
        return render_template("normal_user.html", title="User Portal")

    # CASE 3: Failure
    return render_template(
        "login.html",
        title="Login",
        error="Invalid username or password.",
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ----------------------------------------------------
# CLUE 1
# ----------------------------------------------------
@app.route("/clue1")
def clue1():
    if "user" not in session:
        return redirect("/login")

    last_word = session.get("last_secret_word", None)

    return render_template("clue1.html", last_word=last_word)


# ----------------------------------------------------
# SEARCH (LEVEL 2)
# ----------------------------------------------------
@app.route("/search")
def search():
    if "user" not in session:
        return redirect("/login")

    term = request.args.get("s", "")
    lower_term = term.lower()

    # STRONG attack → must include UNION + SELECT
    is_union_attack = ("union" in lower_term and "select" in lower_term)

    # WEAK attacks → quotes, OR 1=1, comment marks, etc.
    is_weak_attack = (
        ("'" in term) or
        ("--" in lower_term) or
        (" or " in lower_term) or
        ("#" in lower_term) or
        ("/*" in lower_term)
    )

    # Dangerous only means “SQLi-looking” (for visual effects)
    # but only UNION SELECT gives a reward.
    dangerous = is_union_attack or is_weak_attack

    query = f"SELECT id, name, description FROM products WHERE name LIKE '%{term}%'"
    log_injection(term, "/search")

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(query)
        results = cur.fetchall()
        error = None
    except Exception as e:
        results = []
        error = str(e)

    already_awarded = session.get("secret_given_search", False)
    last_word = None

    # ⭐ Only UNION SELECT gets a secret word once
    if is_union_attack:
        if not already_awarded:
            award_random_secret_word()
            session["secret_given_search"] = True
        last_word = session.get("last_secret_word")

    # Weak attack = NO secret word
    # last_word stays None for weak attack

    return render_template(
        "search.html",
        term=term,
        results=results,
        error=error,
        dangerous=dangerous,  # still highlights page
        last_word=last_word,
        already_claimed=already_awarded
    )



# ----------------------------------------------------
# CLUE 2
# ----------------------------------------------------
@app.route("/clue2")
def clue2():
    if "user" not in session:
        return redirect("/login")
    return render_template("clue2.html")


# ----------------------------------------------------
# PRODUCT VIEW (OPTIONAL EXTRA LEVEL)
# ----------------------------------------------------
@app.route("/product/<pid>")
def product(pid):
    if "user" not in session:
        return redirect("/login")

    query = f"SELECT id, name, description, price FROM products WHERE id = {pid}"
    log_injection(pid, "/product")

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(query)
        rows = cur.fetchall()
        error = None
    except Exception as e:
        rows = []
        error = str(e)

    return render_template("product.html", pid=pid, rows=rows, error=error)


# ----------------------------------------------------
# CLUE 3
# ----------------------------------------------------
@app.route("/clue3")
def clue3():
    if "user" not in session:
        return redirect("/login")
    return render_template("clue3.html")


# ----------------------------------------------------
# LEVEL 3 — BLIND SQL INJECTION (Boolean Oracle)
# ----------------------------------------------------
@app.route("/blind", methods=["GET"])
def blind():
    if "user" not in session:
        return redirect("/login")

    payload = request.args.get("id", "")
    lower_p = payload.lower().strip()

    print("RAW BLIND PAYLOAD:", repr(payload))

    # First visit → show the page with no result
    if payload == "":
        return render_template(
            "blind.html",
            result=None,
            dangerous=False,
            already_claimed=False,
            last_word=None,
        )

    # --- STRONG BLIND INJECTION DETECTION -------------------------
    # Payload must contain BOTH:
    #   1. a single quote (')
    #   2. AND one of the advanced blind injection patterns
    is_blind_attack = (
        "'" in payload and
        any(sig in lower_p for sig in ADVANCED_BLIND_INJECTIONS)
    )

    # --- WEAK INJECTIONS (DO NOT REWARD WORDS) ---------------------
    is_weak_attack = (
        (" or " in lower_p and "and" not in lower_p)
        or ( "'" in payload and not is_blind_attack )
    )

    # ---------------------------------------------------------------
    # EXECUTE BOOLEAN QUERY
    # ---------------------------------------------------------------
    boolean = None
    oracle_msg = None

    if is_blind_attack:
        conn = get_db()
        cur = conn.cursor()
        log_injection(payload, "/blind")

        query = f"SELECT 1 FROM users WHERE id='{payload}'"

        try:
            cur.execute(query)
            row = cur.fetchone()
            boolean = True if row else False
        except Exception:
            boolean = False

        conn.close()

        if boolean:
            oracle_msg = "<span style='color:#0f0;'>TRUE — the shadows part.</span>"
        else:
            oracle_msg = "<span style='color:#f55;'>FALSE — darkness remains.</span>"

    # ---------------------------------------------------------------
    # WEAK ATTACK RESPONSE
    # ---------------------------------------------------------------
    if is_weak_attack and not is_blind_attack:
        return render_template(
            "blind.html",
            result=(
                "<span style='color:#f80;'>"
                "“Your magic lacks finesse. This Oracle answers only to precise rituals.”"
                "</span>"
            ),
            dangerous=False,
            already_claimed=False,
            last_word=None,
        )

    # ---------------------------------------------------------------
    # SECRET WORD AWARD SYSTEM
    # ---------------------------------------------------------------
    already_claimed = session.get("secret_given_blind", False)
    last_word = None

    if is_blind_attack:
        if not already_claimed:
            award_random_secret_word()
            last_word = session.get("last_secret_word")
            session["secret_given_blind"] = True

    return render_template(
        "blind.html",
        result=oracle_msg,
        dangerous=is_blind_attack,
        already_claimed=already_claimed,
        last_word=last_word,
    )


# ----------------------------------------------------
# LEVEL 5 — UNION SQLI (File / Schema Dump)
# ----------------------------------------------------
@app.route("/debug", methods=["GET", "POST"])
def debug():
    if "user" not in session:
        return redirect("/login")

    # First arrival — nothing attempted
    if request.method == "GET":
        return render_template(
            "debug.html",
            attempted=False,
            dangerous=False,
            output="",
            last_word=None
        )

    # POST submission
    payload = request.form.get("id", "").strip()
    attempted = True

    if payload == "":
        return render_template(
            "debug.html",
            attempted=True,
            dangerous=False,
            output="<span style='color:#f80;'>The Archive awaits a UNION spell…</span>",
            last_word=None
        )

    lower_payload = payload.lower()

    # Detect UNION attack
    import re
    dangerous = bool(re.search(r"\bunion\b", lower_payload))

    # Log injection attempt
    log_injection(payload, "/debug")

    # Intentionally vulnerable query
    query = f"SELECT username FROM users WHERE id={payload}"

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(query)
        rows = cur.fetchall()
        if rows:
            output = "<br>".join([str(dict(r)) for r in rows])
        else:
            output = "(No output)"
    except Exception as e:
        output = f"<span style='color:#f55;'>SQL Error:</span> {e}"

    conn.close()

    # Award secret every time a correct UNION attack is detected
    last_word = None
    if dangerous:
        last_word = award_random_secret_word()

    return render_template(
        "debug.html",
        attempted=attempted,
        dangerous=dangerous,
        output=output,
        last_word=last_word
    )


# ----------------------------------------------------
# LEVEL 4 — ORDER BY SQL Injection (Column Enumeration)
# ----------------------------------------------------
@app.route("/columns", methods=["GET", "POST"])
def columns():
    if "user" not in session:
        return redirect("/login")

    result_msg = None
    rows_output = None
    dangerous = False
    earned_secret = False
    last_word = None

    if request.method == "POST":
        payload = request.form.get("id", "").strip()
        lower_p = payload.lower()

        if payload == "":
            result_msg = (
                "<span style='color:#f80;'>The chamber is silent. Offer it something…</span>"
            )

        else:
            # Regex detection (strong)
            import re
            is_order_attack = bool(re.search(r"\border\s*by\b", lower_p))
            dangerous = is_order_attack

            if is_order_attack:
                conn = get_db()
                cur = conn.cursor()
                log_injection(payload, "/columns")

                query = f"SELECT id, name, description FROM products WHERE id={payload}"

                try:
                    cur.execute(query)
                    rows = cur.fetchall()
                    rows_output = [dict(r) for r in rows]
                    result_msg = "<span style='color:#0f0;'>VALID — The columns align.</span>"

                except Exception as e:
                    result_msg = (
                        f"<span style='color:#f55;'>INVALID — {e}</span>"
                    )

                conn.close()

                # Always award a secret word for this attack
                last_word = award_random_secret_word()
                earned_secret = True

            else:
                result_msg = (
                    "<span style='color:#f80;'>The chamber only responds to ORDER BY magic…</span>"
                )
                dangerous = False

    return render_template(
        "columns.html",
        result=result_msg,
        rows=rows_output,
        dangerous=dangerous,
        earned_secret=earned_secret,    # NEW
        last_word=last_word
    )

# ----------------------------------------------------
# LEVEL 5 — ADMIN BYPASS
# ----------------------------------------------------
@app.route("/admin_secret", methods=["GET", "POST"])
def admin_secret():
    if request.method == "GET":
        return render_template("admin_secret.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = (
        "SELECT * FROM users WHERE "
        f"username='{username}' AND password='{password}' AND role='admin'"
    )

    log_injection(f"{username} | {password}", "/admin_secret")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(query)
    row = cur.fetchone()
    conn.close()

    # Basic SQLi detection
    is_sql_injection = (
        "'" in username or "--" in username or " or " in username.lower()
        or "'" in password or "--" in password
    )

    if not row:
        return render_template("admin_secret.html", error="Access denied.")

    # Successful login – treat as reached via SQL injection for the game
    session["user"] = "admin"
    session["role"] = "admin"

    already_claimed = session.get("secret_given_admin_secret", False)
    last_word = None

    if is_sql_injection and not already_claimed:
        award_random_secret_word()
        last_word = session.get("last_secret_word")
        session["secret_given_admin_secret"] = True
    elif is_sql_injection and already_claimed:
        last_word = session.get("last_secret_word")

    return render_template(
        "admin_secret_win.html",
        already_claimed=already_claimed,
        last_word=last_word,
    )


# ----------------------------------------------------
# ADMIN LOGS (optional treasure)
# ----------------------------------------------------
@app.route("/admin/logs")
def admin_logs():
    if "user" not in session or session.get("role") != "admin":
        return "Forbidden. Maybe become admin using SQL…"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT username, ip, endpoint, payload, created_at FROM injection_logs "
        "ORDER BY created_at DESC LIMIT 200"
    )
    logs = cur.fetchall()
    conn.close()

    text = ""
    for log in logs:
        text += (
            f"{log['created_at']} | {log['username']} | {log['ip']} "
            f"| {log['endpoint']} | {log['payload']}\n"
        )

    text += "\nFLAG: SQL-CTF-WELL-DONE\nVisit /victory\n"

    return render_template("admin_logs.html", LOG_ENTRIES=text)

# ----------------------------------------------------
# FINAL PHRASE — Validate the Ancient Sentence
# ----------------------------------------------------
@app.route("/final_phrase", methods=["POST"])
def final_phrase():
    if "user" not in session:
        return redirect("/login")

    phrase = request.form.get("phrase", "").strip()

    # The correct full sentence
    correct = "SQL IS A LOCK INJECTION IS THE KEY"

    # Normalize input
    cleaned = " ".join(phrase.upper().split())

    # If correct → final chamber
    if cleaned == correct:
        session["final_phrase_solved"] = True
        return redirect("/victory")

    # If wrong → return error to page
    error = (
        "⚠️ The Ancient Sentence you speak is incorrect.<br>"
        "The chamber rejects your incantation."
    )

    return render_template("final_phrase.html", error=error, entered=phrase)


# ----------------------------------------------------
# VICTORY
# ----------------------------------------------------
@app.route("/victory")
def victory():
    if "user" not in session or session.get("role") != "admin":
        return redirect("/login")
    return render_template("victory.html")


# ----------------------------------------------------
# MAIN
# ----------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
