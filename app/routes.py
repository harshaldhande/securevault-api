import re
import sqlite3
import time
from functools import wraps

from flask import Blueprint, g, jsonify, request

from app.database import get_db
from app.security import (
    create_session_token,
    hash_password,
    hash_session_token,
    verify_password,
)

api = Blueprint("api", __name__)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
SESSION_SECONDS = 60 * 60


def read_json_object():
    if not request.is_json:
        return None

    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def require_auth(view):
    """Validate the opaque bearer token on every protected request."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")
        parts = authorization.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify(error="Authentication required"), 401

        token = parts[1]

        if len(token) > 256:
            return jsonify(error="Invalid session"), 401

        token_hash = hash_session_token(token)
        now = int(time.time())
        db = get_db()

        try:
            row = db.execute(
                """
                SELECT u.id, u.username, u.role, s.expires_at
                FROM sessions AS s
                JOIN users AS u ON u.id = s.user_id
                WHERE s.token_hash = ?
                """,
                (token_hash,),
            ).fetchone()

            if row is None or row["expires_at"] <= now:
                db.execute(
                    "DELETE FROM sessions WHERE token_hash = ?",
                    (token_hash,),
                )
                db.commit()
                return jsonify(error="Invalid or expired session"), 401

            g.current_user = {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
            }

        finally:
            db.close()

        return view(*args, **kwargs)

    return wrapped


@api.post("/register")
def register():
    data = read_json_object()

    if data is None:
        return jsonify(error="A valid JSON object is required"), 400

    if "role" in data:
        return jsonify(error="Role assignment is not permitted"), 403

    if set(data.keys()) != {"username", "password"}:
        return jsonify(error="Provide only username and password"), 400

    username = data["username"]
    password = data["password"]

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Username and password must be strings"), 400

    username = username.strip()

    if not 3 <= len(username) <= 32:
        return jsonify(error="Username must contain 3 to 32 characters"), 400

    if not USERNAME_PATTERN.fullmatch(username):
        return jsonify(error="Username contains invalid characters"), 400

    if not 12 <= len(password) <= 128:
        return jsonify(error="Password must contain 12 to 128 characters"), 400

    password_hash = hash_password(password)
    db = get_db()

    try:
        cursor = db.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, "user"),
        )
        db.commit()
        user_id = cursor.lastrowid

    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(error="Username already exists"), 409

    finally:
        db.close()

    return jsonify(
        message="Account created successfully",
        user={"id": user_id, "username": username, "role": "user"},
    ), 201


@api.post("/login")
def login():
    data = read_json_object()

    if data is None:
        return jsonify(error="A valid JSON object is required"), 400

    if set(data.keys()) != {"username", "password"}:
        return jsonify(error="Provide only username and password"), 400

    username = data["username"]
    password = data["password"]

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Username and password must be strings"), 400

    username = username.strip()

    if (
        not 3 <= len(username) <= 32
        or not USERNAME_PATTERN.fullmatch(username)
        or not 1 <= len(password) <= 128
    ):
        return jsonify(error="Invalid credentials"), 401

    now = int(time.time())
    db = get_db()

    try:
        attempt = db.execute(
            """
            SELECT failed_count, locked_until
            FROM login_attempts
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if attempt and attempt["locked_until"] > now:
            return jsonify(error="Account temporarily locked"), 429

        if attempt and attempt["locked_until"] > 0:
            db.execute(
                """
                UPDATE login_attempts
                SET failed_count = 0, locked_until = 0
                WHERE username = ?
                """,
                (username,),
            )
            db.commit()

        user = db.execute(
            """
            SELECT id, username, password_hash, role
            FROM users WHERE username = ?
            """,
            (username,),
        ).fetchone()

        valid = (
            user is not None
            and verify_password(user["password_hash"], password)
        )

        if not valid:
            db.execute(
                """
                INSERT INTO login_attempts
                    (username, failed_count, locked_until)
                VALUES (?, 1, 0)
                ON CONFLICT(username) DO UPDATE SET
                    failed_count = login_attempts.failed_count + 1
                """,
                (username,),
            )

            attempt = db.execute(
                """
                SELECT failed_count FROM login_attempts
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

            locked_until = (
                now + LOCKOUT_SECONDS
                if attempt["failed_count"] >= MAX_FAILED_ATTEMPTS
                else 0
            )

            if locked_until:
                db.execute(
                    """
                    UPDATE login_attempts SET locked_until = ?
                    WHERE username = ?
                    """,
                    (locked_until, username),
                )

            db.commit()

            if locked_until:
                return jsonify(error="Account temporarily locked"), 429

            return jsonify(error="Invalid username or password"), 401

        db.execute(
            "DELETE FROM login_attempts WHERE username = ?",
            (username,),
        )

        token = create_session_token()
        db.execute(
            """
            INSERT INTO sessions
                (token_hash, user_id, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                hash_session_token(token),
                user["id"],
                now + SESSION_SECONDS,
                now,
            ),
        )
        db.commit()

        return jsonify(
            message="Login successful",
            token=token,
            token_type="Bearer",
            expires_in=SESSION_SECONDS,
        ), 200

    finally:
        db.close()


@api.post("/records")
@require_auth
def create_record():
    data = read_json_object()

    if data is None:
        return jsonify(error="A valid JSON object is required"), 400

    if set(data.keys()) != {"title", "body"}:
        return jsonify(error="Provide only title and body"), 400

    title = data["title"]
    body = data["body"]

    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify(error="Title and body must be strings"), 400

    if not title.strip() or len(title) > 200:
        return jsonify(error="Title must contain 1 to 200 characters"), 400

    if not body.strip() or len(body) > 10000:
        return jsonify(error="Body must contain 1 to 10000 characters"), 400

    db = get_db()

    try:
        cursor = db.execute(
            """
            INSERT INTO records (user_id, title, body)
            VALUES (?, ?, ?)
            """,
            (g.current_user["id"], title.strip(), body),
        )
        db.commit()
        record_id = cursor.lastrowid
    finally:
        db.close()

    return jsonify(
        message="Record created successfully",
        id=record_id,
    ), 201


@api.get("/records/<int:record_id>")
@require_auth
def get_record(record_id):
    db = get_db()

    try:
        if g.current_user["role"] == "admin":
            record = db.execute(
                """
                SELECT id, user_id, title, body, created_at
                FROM records WHERE id = ?
                """,
                (record_id,),
            ).fetchone()
        else:
            # Ownership is checked in the database query itself.
            record = db.execute(
                """
                SELECT id, user_id, title, body, created_at
                FROM records
                WHERE id = ? AND user_id = ?
                """,
                (record_id, g.current_user["id"]),
            ).fetchone()
    finally:
        db.close()

    if record is None:
        return jsonify(error="Record not found"), 404

    return jsonify(record=dict(record)), 200
