from app import create_app
from app.database import get_db

app = create_app({
    "TESTING": True,
})

client = app.test_client()

username = "step3_test_user"
password = "Test-Password-123!"

# Remove this test account if it exists from an earlier run.
db = get_db()
db.execute("DELETE FROM users WHERE username = ?", (username,))
db.commit()
db.close()

# Test 1: Successful registration
response = client.post("/register", json={
    "username": username,
    "password": password,
})
print("Test 1 - Registration:", response.status_code)
assert response.status_code == 201

# Test 2: Password must not be returned
assert password not in response.get_data(as_text=True)
print("Test 2 - Password not returned: PASS")

# Test 3: Verify stored password hash and role
db = get_db()
user = db.execute(
    "SELECT username, password_hash, role FROM users WHERE username = ?",
    (username,),
).fetchone()
db.close()

assert user is not None
assert user["password_hash"] != password
assert user["password_hash"].startswith("$argon2id$")
assert user["role"] == "user"
print("Test 3 - Argon2 hash and default role: PASS")

# Test 4: Duplicate username
response = client.post("/register", json={
    "username": username,
    "password": password,
})
print("Test 4 - Duplicate username:", response.status_code)
assert response.status_code == 409

# Test 5: Attempted privilege escalation
response = client.post("/register", json={
    "username": "step3_admin_test",
    "password": password,
    "role": "admin",
})
print("Test 5 - Role escalation:", response.status_code)
assert response.status_code == 403

# Test 6: Invalid short password
response = client.post("/register", json={
    "username": "step3_short_test",
    "password": "short",
})
print("Test 6 - Invalid password:", response.status_code)
assert response.status_code == 400

print("\nAll Step 3 registration tests passed.")
