import importlib

from provenance import db as dbmod


def test_web_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "web.db"))
    app_module = importlib.import_module("app")
    app_module.seed.seed(dbmod.connect())  # module may already be imported against another DB
    client = app_module.app.test_client()

    assert client.post("/register", data={"username": "dave", "password": "dave123"}).status_code == 302
    client.post("/login", data={"username": "dave", "password": "dave123"})
    assert b"notes.txt" in client.get("/workspace").data
    # Edit without opening first is blocked by the transition rules
    doc_id = dbmod.connect().execute(
        "SELECT d.doc_id FROM Documents d JOIN Users u ON u.user_id=d.owner_id "
        "WHERE u.username='dave' LIMIT 1").fetchone()[0]
    page = client.post(f"/files/{doc_id}/edit", follow_redirects=True).data
    assert b"Blocked by provenance rules" in page
    assert client.get(f"/files/{doc_id}").status_code == 200  # Open File
    assert b"Saved." in client.post(f"/files/{doc_id}/edit", data={"content": "hi"},
                                    follow_redirects=True).data
    client.get(f"/files/{doc_id}")
    assert b"Deleted" in client.post(f"/files/{doc_id}/delete", follow_redirects=True).data
    assert client.get("/admin").status_code == 403
    client.post("/logout")

    client.post("/login", data={"username": "admin", "password": "admin123"})
    assert b"VALID" in client.get("/admin").data
    page = client.post("/admin/tamper/deletion", follow_redirects=True).data
    assert b"TAMPERING DETECTED" in page and b"EVENT_DELETED" in page
    page = client.post("/admin/undo", follow_redirects=True).data
    assert b"TAMPERING DETECTED" not in page
    assert b"Tampering undone" in page
    page = client.post("/admin/reset", follow_redirects=True).data
    assert b"TAMPERING DETECTED" not in page
    # empty log: tamper is refused and leaves nothing to undo
    page = client.post("/admin/tamper/modification", follow_redirects=True).data
    assert b"Nothing to tamper with yet" in page and b"Undo tampering" not in page
