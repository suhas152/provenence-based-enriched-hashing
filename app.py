"""Flask web app: user workspace (event capture) + admin security dashboard."""
import os
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from provenance import auth, seed, tamper
from provenance.context import TransitionError
from provenance.db import connect, now
from provenance.verify import verify_all

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

_c = connect()
seed.seed(_c)  # creates schema + demo data on first start
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


def own_doc(doc_id):
    doc = db().execute("SELECT * FROM Documents WHERE doc_id=? AND owner_id=? AND deleted=0",
                       (doc_id, g.user["user_id"])).fetchone()
    if doc is None:
        abort(404)
    return doc


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


# ---- User workspace (file + database events) ---------------------------------
@app.route("/workspace")
@login_required
def workspace():
    docs = db().execute("SELECT * FROM Documents WHERE owner_id=? AND deleted=0 ORDER BY name",
                        (g.user["user_id"],)).fetchall()
    return render_template("workspace.html", docs=docs)


@app.route("/files/new", methods=["POST"])
@login_required
def create_file():
    name = (request.form.get("name") or "").strip()[:60]
    if name and capture("Create File", f"doc={name}"):
        db().execute("INSERT INTO Documents (owner_id, name, content, updated_at) VALUES (?,?,?,?)",
                     (g.user["user_id"], name, "", now()))
    return redirect(url_for("workspace"))


@app.route("/files/<int:doc_id>")
@login_required
def open_file(doc_id):
    doc = own_doc(doc_id)
    if not capture("Open File", f"doc={doc['name']}"):
        return redirect(url_for("workspace"))
    return render_template("file.html", doc=doc)


@app.route("/files/<int:doc_id>/edit", methods=["POST"])
@login_required
def edit_file(doc_id):
    doc = own_doc(doc_id)
    if capture("Edit File", f"doc={doc['name']}"):
        db().execute("UPDATE Documents SET content=?, updated_at=? WHERE doc_id=?",
                     (request.form.get("content", ""), now(), doc_id))
        flash("Saved.", "ok")
    return redirect(url_for("workspace"))


@app.route("/files/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_file(doc_id):
    doc = own_doc(doc_id)
    if capture("Delete File", f"doc={doc['name']}"):
        db().execute("UPDATE Documents SET deleted=1, updated_at=? WHERE doc_id=?", (now(), doc_id))
        flash(f"Deleted {doc['name']}.", "ok")
    return redirect(url_for("workspace"))


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
                           scenarios=tamper.SCENARIOS)


@app.route("/admin/tamper/<scenario>", methods=["POST"])
@admin_required
def run_tamper(scenario):
    fn = tamper.SCENARIOS.get(scenario) or abort(404)
    try:
        flash("Tamper applied: " + fn(db()), "error")
    except tamper.TamperError as e:
        flash(str(e), "error")
    return redirect(url_for("dashboard"))


@app.route("/admin/reset", methods=["POST"])
@admin_required
def reset():
    seed.seed(db(), fresh=True)
    admin = db().execute("SELECT user_id FROM Users WHERE role='admin'").fetchone()
    session["sid"] = auth.open_session(db(), admin["user_id"], ip(), request.headers.get("User-Agent"))
    flash("Database reset: empty audit log with only the admin account.", "ok")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
