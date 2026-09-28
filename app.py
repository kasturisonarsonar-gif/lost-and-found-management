import os, sqlite3, time
from functools import wraps
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "change-this-secret"
BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "lostfound.db")
UPLOADS = os.path.join(BASE, "static", "uploads")
os.makedirs(UPLOADS, exist_ok=True)
CATEGORIES = ["Phone", "Wallet", "Bag", "Keys", "Documents", "Books", "Electronics", "Clothing", "Other"]

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()

def init_db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user');
    CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, title TEXT, description TEXT, category TEXT, location TEXT,
        date TEXT, kind TEXT, status TEXT DEFAULT 'open', image TEXT, user_id INTEGER, created REAL);
    CREATE TABLE IF NOT EXISTS claims(id INTEGER PRIMARY KEY, item_id INTEGER, claimant_id INTEGER, proof TEXT, status TEXT DEFAULT 'pending');
    """)
    if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        c.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                  ("Admin", "admin@lf.com", generate_password_hash("admin123"), "admin"))
    c.commit(); c.close()

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if session.get("role") != "admin": abort(403)
        return f(*a, **k)
    return w

@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    kind = request.args.get("kind", "")
    cat = request.args.get("category", "")
    sql, args = "SELECT * FROM items WHERE status!='returned'", []
    if q:
        sql += " AND (title LIKE ? OR description LIKE ? OR location LIKE ?)"; args += [f"%{q}%"] * 3
    if kind in ("lost", "found"):
        sql += " AND kind=?"; args.append(kind)
    if cat:
        sql += " AND category=?"; args.append(cat)
    items = db().execute(sql + " ORDER BY created DESC", args).fetchall()
    return render_template("index.html", items=items, cats=CATEGORIES, q=q, kind=kind, cat=cat)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        try:
            db().execute("INSERT INTO users(name,email,password) VALUES(?,?,?)",
                         (f["name"], f["email"].lower(), generate_password_hash(f["password"])))
            db().commit()
            flash("Account created. You can log in now.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.")
    return render_template("auth.html", mode="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?", (request.form["email"].lower(),)).fetchone()
        if u and check_password_hash(u["password"], request.form["password"]):
            session.update(uid=u["id"], name=u["name"], role=u["role"])
            return redirect(url_for("index"))
        flash("Wrong email or password.")
    return render_template("auth.html", mode="login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/report/<kind>", methods=["GET", "POST"])
@login_required
def report(kind):
    if kind not in ("lost", "found"): abort(404)
    if request.method == "POST":
        f = request.form
        img = ""
        file = request.files.get("image")
        if file and file.filename:
            img = f"{int(time.time())}_{secure_filename(file.filename)}"
            file.save(os.path.join(UPLOADS, img))
        db().execute("INSERT INTO items(title,description,category,location,date,kind,image,user_id,created) VALUES(?,?,?,?,?,?,?,?,?)",
                     (f["title"], f["description"], f["category"], f["location"], f["date"], kind, img, session["uid"], time.time()))
        db().commit()
        flash(f"Your {kind} item report is posted.")
        return redirect(url_for("index"))
    return render_template("report.html", kind=kind, cats=CATEGORIES)

@app.route("/item/<int:iid>", methods=["GET", "POST"])
def item(iid):
    it = db().execute("SELECT items.*, users.name AS owner FROM items JOIN users ON users.id=items.user_id WHERE items.id=?", (iid,)).fetchone()
    if not it: abort(404)
    if request.method == "POST":
        if "uid" not in session: return redirect(url_for("login"))
        db().execute("INSERT INTO claims(item_id,claimant_id,proof) VALUES(?,?,?)", (iid, session["uid"], request.form["proof"]))
        db().execute("UPDATE items SET status='claimed' WHERE id=? AND status='open'", (iid,))
        db().commit()
        flash("Claim sent. The admin will review your proof.")
        return redirect(url_for("item", iid=iid))
    opposite = "found" if it["kind"] == "lost" else "lost"
    matches = db().execute("SELECT * FROM items WHERE kind=? AND category=? AND status!='returned' AND id!=? ORDER BY created DESC LIMIT 4",
                           (opposite, it["category"], iid)).fetchall()
    return render_template("item.html", it=it, matches=matches)

@app.route("/mine")
@login_required
def mine():
    items = db().execute("SELECT * FROM items WHERE user_id=? ORDER BY created DESC", (session["uid"],)).fetchall()
    claims = db().execute("SELECT claims.*, items.title FROM claims JOIN items ON items.id=claims.item_id WHERE claimant_id=?", (session["uid"],)).fetchall()
    return render_template("mine.html", items=items, claims=claims)

@app.route("/admin")
@admin_required
def admin():
    claims = db().execute("""SELECT claims.*, items.title, users.name AS claimant FROM claims
        JOIN items ON items.id=claims.item_id JOIN users ON users.id=claims.claimant_id ORDER BY claims.id DESC""").fetchall()
    items = db().execute("SELECT * FROM items ORDER BY created DESC").fetchall()
    stats = {k: db().execute(q).fetchone()[0] for k, q in {
        "Lost": "SELECT COUNT(*) FROM items WHERE kind='lost'",
        "Found": "SELECT COUNT(*) FROM items WHERE kind='found'",
        "Pending claims": "SELECT COUNT(*) FROM claims WHERE status='pending'",
        "Returned": "SELECT COUNT(*) FROM items WHERE status='returned'"}.items()}
    return render_template("admin.html", claims=claims, items=items, stats=stats)

@app.route("/admin/claim/<int:cid>/<action>")
@admin_required
def claim_action(cid, action):
    c = db().execute("SELECT * FROM claims WHERE id=?", (cid,)).fetchone()
    if not c or action not in ("approve", "reject"): abort(404)
    if action == "approve":
        db().execute("UPDATE claims SET status='approved' WHERE id=?", (cid,))
        db().execute("UPDATE items SET status='returned' WHERE id=?", (c["item_id"],))
    else:
        db().execute("UPDATE claims SET status='rejected' WHERE id=?", (cid,))
        db().execute("UPDATE items SET status='open' WHERE id=? AND status='claimed'", (c["item_id"],))
    db().commit()
    return redirect(url_for("admin"))

@app.route("/admin/delete/<int:iid>")
@admin_required
def delete_item(iid):
    db().execute("DELETE FROM items WHERE id=?", (iid,))
    db().execute("DELETE FROM claims WHERE item_id=?", (iid,))
    db().commit()
    return redirect(url_for("admin"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
