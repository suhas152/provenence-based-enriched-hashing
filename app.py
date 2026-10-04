"""Flask web app: user workspace (event capture) + admin security dashboard."""
import os
import sqlite3
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from provenance import auth, seed, tamper
from provenance import db as dbmod
from provenance.company import COMPANY_NAME, COMPANY_OWNER
from provenance.context import TransitionError
from provenance.db import connect, now
from provenance.verify import verify_all

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
app.jinja_env.globals.update(COMPANY_NAME=COMPANY_NAME, COMPANY_OWNER=COMPANY_OWNER)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

_c = connect()
seed.seed(_c)  # schema, company drive and admin account on first start
_c.close()


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def _close(_exc):
    if "db" in g:
        g.db.close()


def ip():
    """Client IP. Behind Render/Cloudflare the socket address is an internal proxy,
    so prefer the headers those proxies set."""
    for header in ("CF-Connecting-IP", "True-Client-IP"):
        if request.headers.get(header):
            return request.headers[header].strip()[:64]
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.remote_addr or "unknown"


@app.before_request
def load_session():
    g.sess = g.user = None
    if request.endpoint == "static":
        return
    s = auth.get_active_session(db(), session.get("sid"), ip())
    if s is None:
        session.pop("sid", None)
        return
    g.sess = s
    g.user = db().execute("SELECT * FROM Users WHERE user_id=?", (s["user_id"],)).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if g.user["role"] != "admin":
            abort(403)
        return fn(*a, **kw)
    return wrapper


def capture(event_type, details=None):
    """Log an event; returns False (with a message) if the transition is not allowed."""
    try:
        auth.capture(db(), g.sess, event_type, ip(), details)
        return True
    except TransitionError as e:
        flash(f"Blocked by provenance rules: {e}. Open the file first.", "error")
        return False


def get_doc(doc_id):
    """A document the current user may access: the shared company drive or their own files."""
    doc = db().execute("SELECT * FROM Documents WHERE doc_id=? AND deleted=0 AND owner_id IN (?, ?)",
                       (doc_id, g.user["user_id"], COMPANY_OWNER)).fetchone()
    if doc is None:
        abort(404)
    return doc


def doc_ref(doc):
    return f"doc={doc['folder']}/{doc['name']}"


# ---- Authentication -----------------------------------------------------------
@app.route("/")
def index():
    if g.user is None:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard" if g.user["role"] == "admin" else "workspace"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            auth.register_user(db(), request.form["username"], request.form["password"], ip())
            flash("Account created - please log in.", "ok")
            return redirect(url_for("login"))
        except auth.AuthError as e:
            flash(str(e), "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            _user, sid = auth.login(db(), request.form["username"], request.form["password"],
                                    ip(), request.headers.get("User-Agent"))
            session.clear()
            session["sid"] = sid
            return redirect(url_for("index"))
        except auth.AuthError as e:
            flash(str(e), "error")
    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["POST"])
def logout():
    if g.sess:
        auth.logout(db(), g.sess["session_id"], ip())
    session.clear()
    return redirect(url_for("login"))


# ---- Company drive (file + database events) ------------------------------------
@app.route("/workspace")
@login_required
def workspace():
    rows = db().execute(
        "SELECT doc_id, owner_id, folder, name, kind, size, updated_at FROM Documents "
        "WHERE deleted=0 AND owner_id IN (?, ?) ORDER BY folder, name",
        (g.user["user_id"], COMPANY_OWNER)).fetchall()
    folders = {}
    for r in rows:
        folders[r["folder"]] = folders.get(r["folder"], 0) + 1
    current = request.args.get("folder")
    docs = [r for r in rows if not current or r["folder"] == current]
    return render_template("workspace.html", docs=docs, folders=folders, current=current,
                           total=len(rows))


@app.route("/files/new", methods=["POST"])
@login_required
def create_file():
    name = (request.form.get("name") or "").strip()[:60]
    if name and capture("Create File", f"doc=My Files/{name}"):
        db().execute("INSERT INTO Documents (owner_id, folder, name, kind, content, size, updated_at) "
                     "VALUES (?,?,?,?,?,?,?)", (g.user["user_id"], "My Files", name, "text", "", 0, now()))
        flash(f"Created {name}.", "ok")
    return redirect(url_for("workspace", folder="My Files"))


@app.route("/files/<int:doc_id>")
@login_required
def open_file(doc_id):
    doc = get_doc(doc_id)
    if not capture("Open File", doc_ref(doc)):
        return redirect(url_for("workspace"))
    csv_rows = None
    if doc["name"].lower().endswith(".csv"):
        csv_rows = [line.split(",") for line in doc["content"].splitlines() if line.strip()]
    return render_template("file.html", doc=doc, csv_rows=csv_rows)


@app.route("/files/<int:doc_id>/raw")
@login_required
def raw_file(doc_id):
    doc = get_doc(doc_id)
    if doc["kind"] != "pdf":
        abort(404)
    resp = app.response_class(doc["data"], mimetype="application/pdf")
    disposition = "attachment" if request.args.get("download") else "inline"
    resp.headers["Content-Disposition"] = f'{disposition}; filename="{doc["name"]}"'
    return resp


@app.route("/files/<int:doc_id>/edit", methods=["POST"])
@login_required
def edit_file(doc_id):
    doc = get_doc(doc_id)
    if doc["kind"] != "text":
        abort(400)
    if capture("Edit File", doc_ref(doc)):
        content = request.form.get("content", "")
        db().execute("UPDATE Documents SET content=?, size=?, updated_at=? WHERE doc_id=?",
                     (content, len(content.encode()), now(), doc_id))
        flash(f"Saved {doc['name']}.", "ok")
    return redirect(url_for("workspace", folder=doc["folder"]))


@app.route("/files/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_file(doc_id):
    doc = get_doc(doc_id)
    if capture("Delete File", doc_ref(doc)):
        db().execute("UPDATE Documents SET deleted=1, updated_at=? WHERE doc_id=?", (now(), doc_id))
        flash(f"Deleted {doc['name']}.", "ok")
    return redirect(url_for("workspace", folder=doc["folder"]))


@app.route("/activity")
@login_required
def activity():
    capture("Database Access", "query=my_activity")
    rows = db().execute("SELECT * FROM AuditEvents WHERE user_id=? ORDER BY sequence_number DESC "
                        "LIMIT 100", (g.user["user_id"],)).fetchall()
    return render_template("activity.html", rows=rows)


# ---- Admin security dashboard ----------------------------------------------------
@app.route("/admin")
@admin_required
def dashboard():
    c = db()
    report = verify_all(c)
    stats = {
        "total_events": report["total_events"],
        "total_users": c.execute("SELECT COUNT(*) FROM Users").fetchone()[0],
        "active_sessions": c.execute("SELECT COUNT(*) FROM Sessions WHERE is_active=1").fetchone()[0],
        "valid_logs": report["valid_logs"],
        "tampered_logs": report["tampered_logs"],
        "batches": len(report["batches"]),
    }
    history = c.execute("SELECT * FROM VerificationResults ORDER BY result_id DESC LIMIT 5").fetchall()
    return render_template("dashboard.html", r=report, stats=stats, history=history,
                           scenarios=tamper.SCENARIOS, can_undo=os.path.exists(snapshot_path()))


@app.route("/admin/tamper/<scenario>", methods=["POST"])
@admin_required
def run_tamper(scenario):
    fn = tamper.SCENARIOS.get(scenario) or abort(404)
    new_snapshot = not os.path.exists(snapshot_path())
    if new_snapshot:
        copy_db(dbmod.DB_PATH, snapshot_path())  # clean copy for "Undo tampering"
    try:
        flash("Tamper applied: " + fn(db()), "error")
    except tamper.TamperError as e:
        if new_snapshot:
            os.remove(snapshot_path())  # nothing changed, so nothing to undo
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


def snapshot_path():
    return dbmod.DB_PATH + ".snapshot"


def copy_db(src, dst):
    a, b = sqlite3.connect(src), sqlite3.connect(dst)
    a.backup(b)
    a.close()
    b.close()


@app.route("/admin/undo", methods=["POST"])
@admin_required
def undo_tamper():
    if os.path.exists(snapshot_path()):
        g.pop("db").close()
        copy_db(snapshot_path(), dbmod.DB_PATH)
        os.remove(snapshot_path())
        flash("Tampering undone: audit log restored to its state before the first tamper.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/admin/reset", methods=["POST"])
@admin_required
def reset():
    if os.path.exists(snapshot_path()):
        os.remove(snapshot_path())
    seed.seed(db(), fresh=True)
    admin = db().execute("SELECT user_id FROM Users WHERE role='admin'").fetchone()
    session["sid"] = auth.open_session(db(), admin["user_id"], ip(), request.headers.get("User-Agent"))
    flash("Database reset: empty audit log with only the admin account.", "ok")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
