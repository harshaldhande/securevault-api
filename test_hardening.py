from app import create_app
from app.database import get_db
from app.security import hash_session_token

app = create_app({"TESTING": True})
client = app.test_client()

username = "step6_hardening_user"
password = "Hardening-Test-Password-123!"


def cleanup():
    db = get_db()
    try:
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


cleanup()

try:
    # Test 1: Malformed JSON
    response = client.post(
        "/register",
        data='{"username":',
        content_type="application/json",
    )
    assert response.status_code == 400
    print("Test 1 - Malformed JSON rejected: PASS")

    # Test 2: Non-JSON request
    response = client.post(
        "/register",
        data="username=test",
        content_type="text/plain",
    )
    assert response.status_code == 400
    print("Test 2 - Non-JSON request rejected: PASS")

    # Test 3: SQL injection-style username
    response = client.post("/register", json={
        "username": "' OR 1=1 --",
        "password": password,
    })
    assert response.status_code == 400
    print("Test 3 - Invalid injection-style username rejected: PASS")

    # Test 4: Oversized JSON body
    response = client.post(
        "/register",
        data='{"username":"test","password":"' + ("A" * 20000) + '"}',
        content_type="application/json",
    )
    assert response.status_code == 400
    print("Test 4 - Oversized request rejected: PASS")

    # Create a test user.
    response = client.post("/register", json={
        "username": username,
        "password": password,
    })
    assert response.status_code == 201
    print("Setup - Test account created: PASS")

    # Test 5: Missing bearer token
    response = client.post("/records", json={
        "title": "Private record",
        "body": "Private content",
    })
    assert response.status_code == 401
    print("Test 5 - Missing session rejected: PASS")

    # Log in.
    response = client.post("/login", json={
        "username": username,
        "password": password,
    })
    assert response.status_code == 200
    token = response.get_json()["token"]

    # Test 6: Revoke the session in the database.
    db = get_db()
    try:
        db.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (hash_session_token(token),),
        )
        db.commit()
    finally:
        db.close()

    response = client.post(
        "/records",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "Test", "body": "Content"},
    )
    assert response.status_code == 401
    print("Test 6 - Revoked session rejected: PASS")

    # Test 7: Empty title
    response = client.post("/login", json={
        "username": username,
        "password": password,
    })
    assert response.status_code == 200
    token = response.get_json()["token"]

    response = client.post(
        "/records",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "   ", "body": "Content"},
    )
    assert response.status_code == 400
    print("Test 7 - Empty title rejected: PASS")

    # Test 8: Excessively long title
    response = client.post(
        "/records",
        headers={"Authorization": f"Bearer {token}"},
        json={"title": "T" * 201, "body": "Content"},
    )
    assert response.status_code == 400
    print("Test 8 - Oversized title rejected: PASS")

    print("\nAll Step 6 hardening tests passed.")

finally:
    cleanup()
