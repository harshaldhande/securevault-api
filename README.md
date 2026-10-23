# Nestack Secure Records API

A multi-tenant REST API demonstrating secure authentication,
server-side sessions, record-level access control, and input validation.

## Technology Stack

- Python 3.11+
- Flask
- SQLite
- Argon2id password hashing
- pytest

## Features

- User registration and login
- Salted Argon2id password hashes
- Opaque, cryptographically random session tokens
- SHA-256 hashes of session tokens stored in SQLite
- One-hour session expiry
- Five failed login attempts trigger a 15-minute account lockout
- User-owned records
- Admin access to records across users
- Parameterized SQL queries
- JSON input validation and request-size limits

## Project Structure

    app/
      __init__.py
      database.py
      routes.py
      security.py
    instance/
    tests/
    requirements.txt
    run.py
    test_registration.py
    test_login.py
    test_records.py
    test_hardening.py

## Setup

Create and activate a virtual environment:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

Install dependencies:

    python -m pip install --upgrade pip
    pip install -r requirements.txt

Initialize the database:

    python -c "from app.database import init_db; init_db()"

Start the development server:

    python run.py

The API will be available at:

    http://127.0.0.1:5000

Do not expose Flask's development server to the public internet.

## API Endpoints

### POST /register

Request:

    {
      "username": "alice",
      "password": "Example-Password-123!"
    }

Success: HTTP 201.

A new account always receives the user role. Supplying a role field
is rejected.

### POST /login

Request:

    {
      "username": "alice",
      "password": "Example-Password-123!"
    }

Success: HTTP 200.

The response includes an opaque bearer token and its expiry duration.
Invalid credentials return HTTP 401. An account under active lockout
returns HTTP 429.

### POST /records

Requires:

    Authorization: Bearer <token>

Request:

    {
      "title": "Private note",
      "body": "Confidential record contents"
    }

Success: HTTP 201 with the new record ID.

### GET /records/<id>

Requires a valid bearer token.

- The record owner can read their record.
- An admin can read any record.
- Other users receive HTTP 404.
- Missing, invalid, revoked, or expired sessions receive HTTP 401.

## Threat Model

### Password storage

Passwords are hashed with Argon2id using a randomly generated salt.
The database stores the encoded hash and its parameters, not the
plaintext password.

A database-only attacker cannot directly read the original passwords.
They may still attempt offline password guessing, particularly against
weak or reused passwords. Argon2id increases the cost of each guess
but does not make weak passwords unrecoverable.

### Session integrity

The server generates opaque tokens using Python's cryptographically
secure random generator. Only a SHA-256 hash of each token is stored
in the sessions table.

Every protected request hashes the presented bearer token and looks
up an unexpired session. Deleting the session revokes it.

Anyone who steals a live bearer token may use it until it expires
or is revoked. Production deployment must use HTTPS and avoid logging
authorization headers.

### Record-level access control

Normal users retrieve records through a query constrained by both
record ID and authenticated user ID. Authentication alone is not
sufficient to grant access.

Admins use a separate query that permits reading any record.
An inaccessible or nonexistent record returns HTTP 404.

### Privilege escalation

Registration assigns the user role on the server. The public
registration endpoint rejects client-supplied role fields.

There is no public role-change endpoint. Administrative role changes
must be performed through a trusted administrative process with
appropriate authorization and auditing.

### User-table leakage

A leaked users table exposes usernames, password hashes, roles,
and account metadata. Passwords are not stored in plaintext.

An attacker could attempt offline password guessing against the
hashes. A user-table leak alone does not reveal the original session
tokens, because session token hashes are stored separately.

If the attacker also obtains the sessions table, the token hashes
alone should not directly provide usable bearer tokens, but the
combined database and application compromise must be treated as
serious. An attacker with database write access may alter roles or
application data.

### Input and SQL injection

Inputs are checked for expected types and lengths. SQL queries use
placeholders rather than concatenating user input into SQL statements.
The application limits request-body size and returns controlled
client errors for invalid requests.

### Login abuse

Failed login attempts are tracked per account rather than per IP.
Five failures trigger a 15-minute lockout. This helps slow password
guessing but can also allow denial of service through targeted
lockouts. Production systems should consider concurrency-safe
updates, monitoring, recovery procedures, and additional abuse
controls.

## Test Commands

Run the verification scripts sequentially:

    python test_registration.py
    python test_login.py
    python test_records.py
    python test_hardening.py

The scripts cover registration, password hashing, login lockout,
session integrity, record ownership, admin access, and malformed input.

## Limitations and Production Hardening

This is an assessment implementation, not a production-certified service.

Before production use:

- Make failed-login counting and lockout transitions atomic under
  concurrent requests.
- Add rate limiting and monitoring for abuse.
- Provision admins through a controlled, audited administrative
  process.
- Use a production WSGI server and HTTPS.
- Configure secrets and deployment settings outside source control.
- Add structured security logging without passwords or bearer tokens.
- Add integration tests for concurrent login attempts and expiry.
- Consider database backups, recovery, migrations, and audit trails.

## Session Design Decision

Opaque server-side sessions were chosen instead of JWTs because they
support direct revocation and require no client-side signature logic.
The server checks the session database on each protected request.

## Submission Checklist

- [ ] All automated tests pass.
- [ ] README instructions have been verified on a clean setup.
- [ ] No credentials or secrets are committed.
- [ ] GitHub repository is private.
- [ ] Evaluator account roy-nestack is added as collaborator.
- [ ] Repository name follows the required submission format.
