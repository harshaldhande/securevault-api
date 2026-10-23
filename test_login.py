import time

from app import create_app
from app.database import get_db
from app.security import hash_session_token

app = create_app({"TESTING": True})
client = app.test_client()

username = "step4_login_test"
password = "Login-Test-Password-123!"

# Clean up this test account so the script can be rerun.
db = get_db()
db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
db.execute("DELETE FROM users WHERE username = ?", (username,))
db.commit()
db.close()

# Register an account.
response = client.post("/register", json={
    "username": username,
    "password": password,
})
assert response.status_code == 201
print("Setup - Registration: PASS")

# Test 1: Correct credentials.
response = client.post("/login", json={
    "username": username,
    "password": password,
})
assert response.status_code == 200

token = response.get_json()["token"]
assert len(token) >= 40
print("Test 1 - Successful login: PASS")

# Test 2: The database stores only the token hash.
db = get_db()
session = db.execute(
    "SELECT token_hash, expires_at FROM sessions WHERE user_id = "
    "(SELECT id FROM users WHERE username = ?)",
    (username,),
).fetchone()
db.close()

assert session is not None
assert session["token_hash"] == hash_session_token(token)
assert session["token_hash"] != token
assert session["expires_at"] > int(time.time())
print("Test 2 - Hashed session storage and expiry: PASS")

# Test 3: Four failed attempts return 401.
for attempt in range(1, 5):
    response = client.post("/login", json={
        "username": username,
        "password": "Wrong-Password-123!",
    })
    assert response.status_code == 401, (
        f"Attempt {attempt} returned {response.status_code}"
    )

print("Test 3 - First four failures return 401: PASS")

# Test 4: Fifth failed attempt triggers 429.
response = client.post("/login", json={
    "username": username,
    "password": "Wrong-Password-123!",
})
assert response.status_code == 429
print("Test 4 - Fifth failure triggers lockout: PASS")

# Test 5: Correct password cannot bypass an active lockout.
response = client.post("/login", json={
    "username": username,
    "password": password,
})
assert response.status_code == 429
print("Test 5 - Active lockout blocks login: PASS")

# Test 6: Malformed input is rejected.
response = client.post("/login", json={
    "username": username,
})
assert response.status_code == 400
print("Test 6 - Invalid login request: PASS")

print("\nAll Step 4 login tests passed.")
