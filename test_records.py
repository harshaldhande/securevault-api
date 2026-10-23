from app import create_app
from app.database import get_db
from app.security import hash_session_token

app = create_app({"TESTING": True})
client = app.test_client()

password = "Records-Test-Password-123!"
users = ["step5_user_a", "step5_user_b", "step5_admin"]


def cleanup():
    db = get_db()
    try:
        for username in users:
            row = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            db.execute(
                "DELETE FROM login_attempts WHERE username = ?",
                (username,),
            )

            if row:
                db.execute(
                    "DELETE FROM sessions WHERE user_id = ?",
                    (row["id"],),
                )
                db.execute(
                    "DELETE FROM records WHERE user_id = ?",
                    (row["id"],),
                )
                db.execute(
                    "DELETE FROM users WHERE id = ?",
                    (row["id"],),
                )
        db.commit()
    finally:
        db.close()


def register_and_login(username):
    response = client.post("/register", json={
        "username": username,
        "password": password,
    })
    assert response.status_code == 201, response.get_json()

    response = client.post("/login", json={
        "username": username,
        "password": password,
    })
    assert response.status_code == 200, response.get_json()

    return response.get_json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


cleanup()

try:
    token_a = register_and_login(users[0])
    token_b = register_and_login(users[1])

    # Test 1: Unauthenticated record creation is rejected.
    response = client.post("/records", json={
        "title": "Private",
        "body": "Secret content",
    })
    assert response.status_code == 401
    print("Test 1 - Unauthenticated access rejected: PASS")

    # Test 2: User A creates a record.
    response = client.post(
        "/records",
        headers=auth(token_a),
        json={"title": "User A record", "body": "Private A content"},
    )
    assert response.status_code == 201, response.get_json()
    record_id = response.get_json()["id"]
    print("Test 2 - Authenticated record creation: PASS")

    # Test 3: Owner can read the record.
    response = client.get(
        f"/records/{record_id}",
        headers=auth(token_a),
    )
    assert response.status_code == 200
    assert response.get_json()["record"]["body"] == "Private A content"
    print("Test 3 - Owner can read own record: PASS")

    # Test 4: User B cannot read User A's record.
    response = client.get(
        f"/records/{record_id}",
        headers=auth(token_b),
    )
    assert response.status_code == 404
    assert "Private A content" not in response.get_data(as_text=True)
    print("Test 4 - Cross-user access denied: PASS")

    # Test 5: Invalid bearer token is rejected.
    response = client.get(
        f"/records/{record_id}",
        headers=auth("invalid-token"),
    )
    assert response.status_code == 401
    print("Test 5 - Invalid session rejected: PASS")

    # Test 6: Wrongly typed record fields are rejected.
    response = client.post(
        "/records",
        headers=auth(token_a),
        json={"title": 123, "body": "Invalid title type"},
    )
    assert response.status_code == 400
    print("Test 6 - Record input validation: PASS")

    # Test 7: Unknown record returns 404.
    response = client.get("/records/999999", headers=auth(token_a))
    assert response.status_code == 404
    print("Test 7 - Missing record returns 404: PASS")

    # Test 8: Admin can read another user's record.
    token_admin = register_and_login(users[2])

    db = get_db()
    try:
        db.execute(
            "UPDATE users SET role = 'admin' WHERE username = ?",
            (users[2],),
        )
        db.commit()
    finally:
        db.close()

    # Revoke the pre-role-change session and log in again.
    db = get_db()
    try:
        admin_id = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (users[2],),
        ).fetchone()["id"]
        db.execute("DELETE FROM sessions WHERE user_id = ?", (admin_id,))
        db.commit()
    finally:
        db.close()

    response = client.post("/login", json={
        "username": users[2],
        "password": password,
    })
    assert response.status_code == 200
    token_admin = response.get_json()["token"]

    response = client.get(
        f"/records/{record_id}",
        headers=auth(token_admin),
    )
    assert response.status_code == 200
    assert response.get_json()["record"]["user_id"] != admin_id
    print("Test 8 - Admin can read another user's record: PASS")

    # Test 9: Expired session is rejected.
    db = get_db()
    try:
        db.execute(
            "UPDATE sessions SET expires_at = 1 WHERE token_hash = ?",
            (hash_session_token(token_a),),
        )
        db.commit()
    finally:
        db.close()

    response = client.get(
        f"/records/{record_id}",
        headers=auth(token_a),
    )
    assert response.status_code == 401
    print("Test 9 - Expired session rejected: PASS")

    print("\nAll Step 5 record security tests passed.")

finally:
    cleanup()
