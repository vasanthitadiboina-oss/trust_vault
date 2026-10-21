"""Application services and persistence for the Trust Vault Flask API.

This module contains no Flask routes or request handling. Route handlers pass
their inputs and request-scoped SQLite connection into these functions.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

import jwt
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"doc", "docx", "jpeg", "jpg", "pdf", "png", "txt"}
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
PASSWORD_MIN_LENGTH = 12
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ROLE_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,49}$")
PERMISSIONS = {
    "auth.profile": "View the authenticated user's profile",
    "auth.logout": "Log out and revoke the current access token",
    "documents.upload": "Upload documents",
    "documents.list": "List owned and shared documents",
    "documents.read": "Read accessible document metadata",
    "documents.download": "Download accessible documents",
    "access_requests.create": "Request access to documents",
    "access_requests.list": "List access requests visible to the user",
    "access_requests.review": "Approve or reject requests for owned documents",
    "roles.manage": "Manage roles, permissions, and user role assignments",
    "audit.read": "Read audit events",
}
DEFAULT_USER_PERMISSIONS = {
    "auth.profile",
    "auth.logout",
    "documents.upload",
    "documents.list",
    "documents.read",
    "documents.download",
    "access_requests.create",
    "access_requests.list",
    "access_requests.review",
}


class ServiceError(Exception):
    """An expected application failure that should be returned to the API caller."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect_database(database_path: str) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database(database_path: str) -> None:
    """Create the schema. Safe to call on application startup."""
    connection = connect_database(database_path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
                role_id INTEGER REFERENCES roles(id),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description TEXT NOT NULL DEFAULT '',
                is_system INTEGER NOT NULL DEFAULT 0 CHECK (is_system IN (0, 1)),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
                permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
                PRIMARY KEY (role_id, permission_id)
            );
            CREATE TABLE IF NOT EXISTS user_permission_sets (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_permissions (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, permission_id)
            );
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                storage_name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS access_requests (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                reason TEXT NOT NULL,
                suggestion TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected')),
                created_at TEXT NOT NULL,
                reviewed_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_pending_request_per_user_document
                ON access_requests (document_id, requester_id) WHERE status = 'pending';
            CREATE TABLE IF NOT EXISTS document_grants (
                document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                request_id TEXT NOT NULL UNIQUE REFERENCES access_requests(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL,
                PRIMARY KEY (document_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS auth_tokens_user_id ON auth_tokens (user_id);
            """
        )
        user_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(users)")
        }
        if "role_id" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id)"
            )

        now = utc_now()
        connection.executemany(
            """INSERT OR IGNORE INTO permissions (name, description)
               VALUES (?, ?)""",
            PERMISSIONS.items(),
        )
        connection.executemany(
            """INSERT OR IGNORE INTO roles (name, description, is_system, created_at)
               VALUES (?, ?, 1, ?)""",
            [
                ("user", "Default account role", now),
                ("admin", "System administrator role", now),
            ],
        )
        connection.execute(
            """UPDATE users
               SET role_id = (SELECT id FROM roles WHERE roles.name = users.role)
               WHERE role_id IS NULL"""
        )
        connection.execute(
            """INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
               SELECT roles.id, permissions.id FROM roles, permissions
               WHERE roles.name = 'admin'"""
        )
        connection.execute(
            """INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
               SELECT roles.id, permissions.id FROM roles, permissions
               WHERE roles.name = 'user' AND permissions.name IN
                     ('auth.profile', 'auth.logout', 'documents.upload',
                      'documents.list', 'documents.read', 'documents.download',
                      'access_requests.create', 'access_requests.list',
                      'access_requests.review')"""
        )
        connection.execute("PRAGMA user_version = 3")
        connection.commit()
    finally:
        connection.close()


def get_role_permissions(connection: sqlite3.Connection, role_id: int) -> list[str]:
    rows = connection.execute(
        """SELECT p.name FROM permissions p
           JOIN role_permissions rp ON rp.permission_id = p.id
           WHERE rp.role_id = ? ORDER BY p.name""",
        (role_id,),
    ).fetchall()
    return [row["name"] for row in rows]


def get_user_permissions(connection: sqlite3.Connection, user_id: int) -> list[str]:
    user = connection.execute(
        "SELECT role_id FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        return []
    has_override = connection.execute(
        "SELECT 1 FROM user_permission_sets WHERE user_id = ?", (user_id,)
    ).fetchone()
    if has_override:
        rows = connection.execute(
            """SELECT permissions.name FROM user_permissions
               JOIN permissions ON permissions.id = user_permissions.permission_id
               WHERE user_permissions.user_id = ? ORDER BY permissions.name""",
            (user_id,),
        ).fetchall()
        return [row["name"] for row in rows]
    return get_role_permissions(connection, user["role_id"])


def user_inherits_role_permissions(connection: sqlite3.Connection, user_id: int) -> bool:
    return connection.execute(
        "SELECT 1 FROM user_permission_sets WHERE user_id = ?", (user_id,)
    ).fetchone() is None


def get_user_permission_settings(
    connection: sqlite3.Connection, user_id: int
) -> dict[str, Any]:
    user = get_user_by_id(connection, user_id)
    if user is None:
        raise ServiceError(404, "User not found.")
    return {
        **public_user(user, get_user_permissions(connection, user_id)),
        "inherits_role": user_inherits_role_permissions(connection, user_id),
    }


def _validated_permission_names(permission_names: Any) -> list[str]:
    if (
        not isinstance(permission_names, list)
        or any(not isinstance(name, str) for name in permission_names)
        or len(permission_names) != len(set(permission_names))
    ):
        raise ServiceError(400, "Permissions must be a list of unique permission names.")
    unknown = set(permission_names) - PERMISSIONS.keys()
    if unknown:
        raise ServiceError(400, f"Unknown permissions: {', '.join(sorted(unknown))}.")
    return sorted(permission_names)


def public_user(
    user: sqlite3.Row, permissions: list[str] | None = None
) -> dict[str, Any]:
    result = {"id": user["id"], "email": user["email"], "role": user["role"]}
    if "role_id" in user.keys():
        result["role_id"] = user["role_id"]
    if permissions is not None:
        result["permissions"] = permissions
    return result


def get_user_by_id(connection: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return connection.execute(
        """SELECT users.id, users.email, roles.name AS role, users.role_id
           FROM users JOIN roles ON roles.id = users.role_id
           WHERE users.id = ?""",
        (user_id,),
    ).fetchone()


def record_audit(
    connection: sqlite3.Connection,
    actor_id: int | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    **details: Any,
) -> None:
    """Add an audit row to the caller's transaction."""
    connection.execute(
        """INSERT INTO audit_log
           (actor_id, action, resource_type, resource_id, details, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            actor_id,
            action,
            resource_type,
            resource_id,
            json.dumps(details, separators=(",", ":"), sort_keys=True),
            utc_now(),
        ),
    )


def _request_data(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ServiceError(400, "Expected a JSON object.")
    return data


def _validated_credentials(payload: dict[str, Any]) -> tuple[str, str]:
    email = payload.get("email")
    password = payload.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        raise ServiceError(400, "Email and password are required.")
    email = email.strip().casefold()
    if len(email) > 254 or not _EMAIL_PATTERN.fullmatch(email):
        raise ServiceError(400, "Enter a valid email address.")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ServiceError(400, f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
    return email, password


def create_user(
    connection: sqlite3.Connection,
    actor_id: int | None,
    data: Any,
    *,
    default_role: bool,
) -> dict[str, Any]:
    payload = _request_data(data)
    email, password = _validated_credentials(payload)

    requested_role_id = payload.get("role_id")
    if default_role:
        role = connection.execute(
            "SELECT id, name FROM roles WHERE name = 'user'"
        ).fetchone()
    elif requested_role_id is None:
        role = connection.execute(
            "SELECT id, name FROM roles WHERE name = 'user'"
        ).fetchone()
    elif isinstance(requested_role_id, int) and not isinstance(requested_role_id, bool):
        role = connection.execute(
            "SELECT id, name FROM roles WHERE id = ?", (requested_role_id,)
        ).fetchone()
    else:
        raise ServiceError(400, "role_id must be an integer.")
    if role is None and default_role:
        raise RuntimeError("Default user role is missing from the database.")
    if role is None:
        raise ServiceError(404, "Role not found.")
    permission_names = None
    if not default_role and "permissions" in payload:
        permission_names = _validated_permission_names(payload["permissions"])
    try:
        with connection:
            cursor = connection.execute(
                """INSERT INTO users (email, password_hash, role_id, created_at)
                   VALUES (?, ?, ?, ?)""",
                (email, generate_password_hash(password), role["id"], utc_now()),
            )
            user = {
                "id": cursor.lastrowid,
                "email": email,
                "role": role["name"],
                "role_id": role["id"],
            }
            if permission_names is not None:
                permission_rows = connection.execute(
                    "SELECT id FROM permissions WHERE name IN ({})".format(
                        ",".join("?" for _ in permission_names) or "NULL"
                    ),
                    permission_names,
                ).fetchall()
                connection.execute(
                    "INSERT INTO user_permission_sets (user_id, updated_at) VALUES (?, ?)",
                    (user["id"], utc_now()),
                )
                connection.executemany(
                    "INSERT INTO user_permissions (user_id, permission_id) VALUES (?, ?)",
                    [(user["id"], row["id"]) for row in permission_rows],
                )
            record_audit(
                connection,
                actor_id if actor_id is not None else user["id"],
                "user.created" if actor_id is not None else "user.registered",
                "user",
                str(user["id"]),
                role=role["name"],
            )
    except sqlite3.IntegrityError as exception:
        if "users.email" in str(exception).lower() or "unique" in str(exception).lower():
            raise ServiceError(409, "An account with that email already exists.") from exception
        raise
    return {
        **public_user(user, get_user_permissions(connection, user["id"])),
        "role_id": role["id"],
        "inherits_role": permission_names is None,
    }


def register_user(connection: sqlite3.Connection, data: Any) -> dict[str, Any]:
    return create_user(connection, None, data, default_role=True)


def bootstrap_admin(connection: sqlite3.Connection, data: Any) -> dict[str, Any]:
    email, password = _validated_credentials(_request_data(data))
    user_role = connection.execute(
        "SELECT id FROM roles WHERE name = 'user'"
    ).fetchone()
    admin_role = connection.execute(
        "SELECT id FROM roles WHERE name = 'admin'"
    ).fetchone()
    if user_role is None or admin_role is None:
        raise RuntimeError("System roles are missing from the database.")

    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            admin_count = connection.execute(
                """SELECT COUNT(*) FROM users
                   JOIN roles ON roles.id = users.role_id
                   WHERE roles.name = 'admin'"""
            ).fetchone()[0]
            if admin_count:
                raise ServiceError(409, "Administrator setup has already been completed.")

            user = connection.execute(
                "SELECT id, password_hash FROM users WHERE email = ?",
                (email,),
            ).fetchone()
            if user is None:
                cursor = connection.execute(
                    """INSERT INTO users (email, password_hash, role_id, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (email, generate_password_hash(password), user_role["id"], utc_now()),
                )
                user_id = cursor.lastrowid
                action = "user.registered"
            else:
                if not check_password_hash(user["password_hash"], password):
                    raise ServiceError(401, "Invalid email or password.")
                user_id = user["id"]
                action = "user.role_changed"

            connection.execute(
                "UPDATE users SET role = 'admin', role_id = ? WHERE id = ?",
                (admin_role["id"], user_id),
            )
            record_audit(
                connection,
                user_id,
                action,
                "user",
                str(user_id),
                new_role="admin",
                source="localhost_bootstrap",
            )
    except sqlite3.IntegrityError as exception:
        if "users.email" in str(exception).lower() or "unique" in str(exception).lower():
            raise ServiceError(409, "An account with that email already exists.") from exception
        raise

    return {
        "id": user_id,
        "email": email,
        "role": "admin",
        "role_id": admin_role["id"],
        "permissions": get_role_permissions(connection, admin_role["id"]),
    }


def create_user_by_admin(
    connection: sqlite3.Connection, actor_id: int, data: Any
) -> dict[str, Any]:
    return create_user(connection, actor_id, data, default_role=False)


def authenticate_user(connection: sqlite3.Connection, data: Any) -> dict[str, Any]:
    payload = _request_data(data)
    email = payload.get("email")
    password = payload.get("password")
    if not isinstance(email, str) or not isinstance(password, str):
        raise ServiceError(400, "Email and password are required.")

    user = connection.execute(
        """SELECT users.id, users.email, users.password_hash,
                  roles.name AS role, users.role_id
           FROM users JOIN roles ON roles.id = users.role_id
           WHERE users.email = ?""",
        (email.strip().casefold(),),
    ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        with connection:
            record_audit(
                connection,
                user["id"] if user else None,
                "auth.login_failed",
                "user",
                str(user["id"]) if user else None,
            )
        raise ServiceError(401, "Invalid email or password.")

    with connection:
        record_audit(connection, user["id"], "auth.login", "user", str(user["id"]))
    return public_user(user, get_user_permissions(connection, user["id"]))


def update_user_credentials(
    connection: sqlite3.Connection, user_id: int, data: Any
) -> dict[str, Any]:
    payload = _request_data(data)
    current_password = payload.get("current_password")
    if not isinstance(current_password, str):
        raise ServiceError(400, "Current password is required.")
    email, password = _validated_credentials(payload)

    user = connection.execute(
        """SELECT users.id, users.password_hash, users.role_id, roles.name AS role
           FROM users JOIN roles ON roles.id = users.role_id
           WHERE users.id = ?""",
        (user_id,),
    ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], current_password):
        raise ServiceError(401, "Current password is incorrect.")

    try:
        with connection:
            connection.execute(
                """UPDATE users SET email = ?, password_hash = ?
                   WHERE id = ?""",
                (email, generate_password_hash(password), user_id),
            )
            connection.execute(
                "UPDATE auth_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                (utc_now(), user_id),
            )
            record_audit(
                connection,
                user_id,
                "user.credentials_changed",
                "user",
                str(user_id),
            )
    except sqlite3.IntegrityError as exception:
        if "users.email" in str(exception).lower() or "unique" in str(exception).lower():
            raise ServiceError(409, "An account with that email already exists.") from exception
        raise

    return public_user(
        {
            "id": user["id"],
            "email": email,
            "role": user["role"],
            "role_id": user["role_id"],
        },
        get_user_permissions(connection, user_id),
    )


def issue_access_token(
    connection: sqlite3.Connection,
    user: dict[str, Any],
    secret_key: str,
    issuer: str,
    audience: str,
    expires_in: int,
) -> str:
    issued_at = int(datetime.now(timezone.utc).timestamp())
    expires_at = issued_at + expires_in
    token_id = str(uuid.uuid4())
    claims = {
        "sub": str(user["id"]),
        "jti": token_id,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "iss": issuer,
        "aud": audience,
        "token_type": "access",
    }
    token = jwt.encode(claims, secret_key, algorithm="HS256")
    with connection:
        connection.execute(
            "DELETE FROM auth_tokens WHERE expires_at <= ?",
            (issued_at,),
        )
        connection.execute(
            "INSERT INTO auth_tokens (token_id, user_id, expires_at) VALUES (?, ?, ?)",
            (token_id, user["id"], expires_at),
        )
    return token


def authenticate_access_token(
    connection: sqlite3.Connection,
    token: str,
    secret_key: str,
    issuer: str,
    audience: str,
) -> tuple[sqlite3.Row, str]:
    try:
        claims = jwt.decode(
            token,
            secret_key,
            algorithms=["HS256"],
            issuer=issuer,
            audience=audience,
            options={"require": ["sub", "jti", "iat", "nbf", "exp", "iss", "aud", "token_type"]},
        )
    except jwt.InvalidTokenError as exception:
        raise ServiceError(401, "Invalid or expired access token.") from exception

    if claims.get("token_type") != "access":
        raise ServiceError(401, "Invalid or expired access token.")
    try:
        user_id = int(claims["sub"])
    except (TypeError, ValueError) as exception:
        raise ServiceError(401, "Invalid or expired access token.") from exception

    token_row = connection.execute(
        """SELECT u.id, u.email, r.name AS role, u.role_id, t.token_id
           FROM auth_tokens t JOIN users u ON u.id = t.user_id
           JOIN roles r ON r.id = u.role_id
           WHERE t.token_id = ? AND t.user_id = ? AND t.revoked_at IS NULL
             AND t.expires_at > ?""",
        (claims["jti"], user_id, int(datetime.now(timezone.utc).timestamp())),
    ).fetchone()
    if token_row is None:
        raise ServiceError(401, "Invalid or expired access token.")
    return token_row, token_row["token_id"]


def logout_user(
    connection: sqlite3.Connection, user_id: int, token_id: str | None = None
) -> None:
    with connection:
        if token_id is not None:
            connection.execute(
                """UPDATE auth_tokens SET revoked_at = ?
                   WHERE token_id = ? AND user_id = ? AND revoked_at IS NULL""",
                (utc_now(), token_id, user_id),
            )
        record_audit(connection, user_id, "auth.logout", "user", str(user_id))


def promote_admin(database_path: str, email: str) -> None:
    normalized_email = email.strip().casefold()
    connection = connect_database(database_path)
    try:
        with connection:
            cursor = connection.execute(
                """UPDATE users SET role = 'admin',
                   role_id = (SELECT id FROM roles WHERE name = 'admin')
                   WHERE email = ?""",
                (normalized_email,),
            )
            if cursor.rowcount != 1:
                raise ServiceError(404, "No account found with that email.")
            user = connection.execute(
                "SELECT id FROM users WHERE email = ?", (normalized_email,)
            ).fetchone()
            record_audit(
                connection,
                user["id"],
                "user.role_changed",
                "user",
                str(user["id"]),
                new_role="admin",
                source="local_cli",
            )
    finally:
        connection.close()


def list_permissions(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT id, name, description FROM permissions ORDER BY name"
    ).fetchall()
    return [dict(row) for row in rows]


def list_roles(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    roles = connection.execute(
        "SELECT id, name, description, is_system FROM roles ORDER BY name"
    ).fetchall()
    return [{
        "id": role["id"],
        "name": role["name"],
        "description": role["description"],
        "is_system": bool(role["is_system"]),
        "permissions": get_role_permissions(connection, role["id"]),
    } for role in roles]


def create_role(
    connection: sqlite3.Connection, actor_id: int, data: Any
) -> dict[str, Any]:
    payload = _request_data(data)
    name = payload.get("name")
    description = payload.get("description", "")
    if not isinstance(name, str) or not _ROLE_NAME_PATTERN.fullmatch(name):
        raise ServiceError(
            400,
            "Role name must be 2-50 characters: start with a letter and use lowercase letters, digits, '_' or '-'.",
        )
    if not isinstance(description, str) or len(description) > 250:
        raise ServiceError(400, "Description must be a string of at most 250 characters.")
    name = name.casefold()
    try:
        with connection:
            cursor = connection.execute(
                """INSERT INTO roles (name, description, is_system, created_at)
                   VALUES (?, ?, 0, ?)""",
                (name, description.strip(), utc_now()),
            )
            role_id = cursor.lastrowid
            record_audit(
                connection,
                actor_id,
                "role.created",
                "role",
                str(role_id),
                name=name,
            )
    except sqlite3.IntegrityError as exception:
        if "unique" in str(exception).lower():
            raise ServiceError(409, "A role with that name already exists.") from exception
        raise
    return {
        "id": role_id,
        "name": name,
        "description": description.strip(),
        "is_system": False,
        "permissions": [],
    }


def set_role_permissions(
    connection: sqlite3.Connection, actor_id: int, role_id: int, data: Any
) -> dict[str, Any]:
    payload = _request_data(data)
    permission_names = _validated_permission_names(payload.get("permissions"))
    role = connection.execute(
        "SELECT id, name, is_system FROM roles WHERE id = ?", (role_id,)
    ).fetchone()
    if role is None:
        raise ServiceError(404, "Role not found.")
    if role["name"] == "admin" and "roles.manage" not in permission_names:
        raise ServiceError(409, "The administrator role must retain roles.manage.")

    permission_rows = connection.execute(
        "SELECT id, name FROM permissions WHERE name IN ({})".format(
            ",".join("?" for _ in permission_names) or "NULL"
        ),
        permission_names,
    ).fetchall()
    with connection:
        connection.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
        connection.executemany(
            "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
            [(role_id, row["id"]) for row in permission_rows],
        )
        record_audit(
            connection,
            actor_id,
            "role.permissions_changed",
            "role",
            str(role_id),
            permissions=sorted(permission_names),
        )
    return {
        "id": role["id"],
        "name": role["name"],
        "permissions": sorted(permission_names),
    }


def set_user_permissions(
    connection: sqlite3.Connection, actor_id: int, user_id: int, data: Any
) -> dict[str, Any]:
    payload = _request_data(data)
    user = get_user_by_id(connection, user_id)
    if user is None:
        raise ServiceError(404, "User not found.")

    if payload.get("inherit_role") is True:
        if "permissions" in payload:
            raise ServiceError(400, "Provide permissions or inherit_role, not both.")
        with connection:
            connection.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
            connection.execute("DELETE FROM user_permission_sets WHERE user_id = ?", (user_id,))
            record_audit(
                connection,
                actor_id,
                "user.permissions_inherited",
                "user",
                str(user_id),
            )
    else:
        permission_names = _validated_permission_names(payload.get("permissions"))
        if user["role"] == "admin" and "roles.manage" not in permission_names:
            admin_rows = connection.execute(
                """SELECT users.id FROM users
                   JOIN roles ON roles.id = users.role_id
                   WHERE roles.name = 'admin' AND users.id != ?""",
                (user_id,),
            ).fetchall()
            another_admin_has_access = any(
                "roles.manage" in get_user_permissions(connection, row["id"])
                for row in admin_rows
            )
            if not another_admin_has_access:
                raise ServiceError(409, "The last administrator must retain roles.manage.")
        permission_rows = connection.execute(
            "SELECT id FROM permissions WHERE name IN ({})".format(
                ",".join("?" for _ in permission_names) or "NULL"
            ),
            permission_names,
        ).fetchall()
        with connection:
            connection.execute(
                """INSERT INTO user_permission_sets (user_id, updated_at) VALUES (?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET updated_at = excluded.updated_at""",
                (user_id, utc_now()),
            )
            connection.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
            connection.executemany(
                "INSERT INTO user_permissions (user_id, permission_id) VALUES (?, ?)",
                [(user_id, row["id"]) for row in permission_rows],
            )
            record_audit(
                connection,
                actor_id,
                "user.permissions_changed",
                "user",
                str(user_id),
                permissions=permission_names,
            )

    return get_user_permission_settings(connection, user_id)


def set_user_role(
    connection: sqlite3.Connection, actor_id: int, user_id: int, data: Any
) -> dict[str, Any]:
    payload = _request_data(data)
    role_id = payload.get("role_id")
    if role_id is None:
        role_name = payload.get("role")
        if not isinstance(role_name, str):
            raise ServiceError(400, "Provide a role_id.")
        role = connection.execute(
            "SELECT id, name FROM roles WHERE name = ? COLLATE NOCASE",
            (role_name,),
        ).fetchone()
    elif isinstance(role_id, int) and not isinstance(role_id, bool):
        role = connection.execute(
            "SELECT id, name FROM roles WHERE id = ?", (role_id,)
        ).fetchone()
    else:
        raise ServiceError(400, "role_id must be an integer.")
    if role is None:
        raise ServiceError(404, "Role not found.")
    target = connection.execute(
        """SELECT users.id, users.email, users.role_id, roles.name AS role
           FROM users JOIN roles ON roles.id = users.role_id
           WHERE users.id = ?""",
        (user_id,),
    ).fetchone()
    if target is None:
        raise ServiceError(404, "User not found.")
    if target["role"] == "admin" and role["name"] != "admin":
        admin_count = connection.execute(
            """SELECT COUNT(*) FROM users
               JOIN roles ON roles.id = users.role_id WHERE roles.name = 'admin'"""
        ).fetchone()[0]
        if admin_count <= 1:
            raise ServiceError(409, "The last administrator cannot be demoted.")
    with connection:
        legacy_role = role["name"] if role["name"] in {"user", "admin"} else "user"
        connection.execute(
            "UPDATE users SET role = ?, role_id = ? WHERE id = ?",
            (legacy_role, role["id"], user_id),
        )
        record_audit(
            connection,
            actor_id,
            "user.role_changed",
            "user",
            str(user_id),
            old_role=target["role"],
            new_role=role["name"],
        )
    return {
        "id": target["id"],
        "email": target["email"],
        "role": role["name"],
        "role_id": role["id"],
        "permissions": get_user_permissions(connection, user_id),
    }


def user_has_permission(
    connection: sqlite3.Connection, user_id: int, permission_name: str
) -> bool:
    return permission_name in get_user_permissions(connection, user_id)


def _document_json(document: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": document["id"],
        "filename": document["original_name"],
        "owner_id": document["owner_id"],
        "created_at": document["created_at"],
    }


def _accessible_document(
    connection: sqlite3.Connection, user_id: int, document_id: str
) -> sqlite3.Row | None:
    return connection.execute(
        """SELECT d.* FROM documents d
           LEFT JOIN document_grants grant_row
             ON grant_row.document_id = d.id AND grant_row.user_id = ?
           WHERE d.id = ? AND (d.owner_id = ? OR grant_row.user_id IS NOT NULL)""",
        (user_id, document_id, user_id),
    ).fetchone()


def upload_document(
    connection: sqlite3.Connection,
    owner_id: int,
    filename: str | None,
    stream: BinaryIO,
    upload_folder: str,
) -> dict[str, Any]:
    if not filename:
        raise ServiceError(400, "Provide a file in the 'file' field.")
    original_name = secure_filename(filename)
    if not original_name or "." not in original_name:
        raise ServiceError(400, "Filename must have a supported extension.")
    extension = original_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ServiceError(415, "Unsupported file type.")

    document_id = str(uuid.uuid4())
    storage_name = f"{uuid.uuid4().hex}.{extension}"
    target = Path(upload_folder) / storage_name
    total = 0
    stored = False
    try:
        with target.open("xb") as destination:
            while chunk := stream.read(64 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise ServiceError(413, "Upload exceeds the 16 MiB limit.")
                destination.write(chunk)
        if total == 0:
            raise ServiceError(400, "Empty files are not accepted.")

        with connection:
            connection.execute(
                """INSERT INTO documents (id, owner_id, original_name, storage_name, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (document_id, owner_id, original_name, storage_name, utc_now()),
            )
            record_audit(
                connection,
                owner_id,
                "document.uploaded",
                "document",
                document_id,
                filename=original_name,
                size_bytes=total,
            )
        stored = True
    finally:
        if not stored and target.exists():
            target.unlink()

    return {
        "id": document_id,
        "filename": original_name,
        "owner_id": owner_id,
        "size_bytes": total,
    }


def list_documents(connection: sqlite3.Connection, user_id: int) -> list[dict[str, Any]]:
    documents = connection.execute(
        """SELECT DISTINCT d.* FROM documents d
           LEFT JOIN document_grants grant_row
             ON grant_row.document_id = d.id AND grant_row.user_id = ?
           WHERE d.owner_id = ? OR grant_row.user_id IS NOT NULL
           ORDER BY d.created_at DESC""",
        (user_id, user_id),
    ).fetchall()
    return [_document_json(document) for document in documents]


def get_accessible_document(
    connection: sqlite3.Connection, user_id: int, document_id: str
) -> dict[str, Any]:
    document = _accessible_document(connection, user_id, document_id)
    if document is None:
        raise ServiceError(404, "Document not found.")
    return _document_json(document)


def get_download(
    connection: sqlite3.Connection, user_id: int, document_id: str, upload_folder: str
) -> tuple[Path, str]:
    document = _accessible_document(connection, user_id, document_id)
    if document is None:
        raise ServiceError(404, "Document not found.")
    path = Path(upload_folder) / document["storage_name"]
    if not path.is_file():
        raise ServiceError(500, "Document content is unavailable.")
    with connection:
        record_audit(connection, user_id, "document.downloaded", "document", document_id)
    return path, document["original_name"]


def create_access_request(
    connection: sqlite3.Connection, requester_id: int, document_id: str, data: Any
) -> dict[str, Any]:
    payload = _request_data(data)
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 1000:
        raise ServiceError(400, "Provide a reason of 1 to 1000 characters.")
    if connection.execute("SELECT 1 FROM documents WHERE id = ?", (document_id,)).fetchone() is None:
        raise ServiceError(404, "Document not found.")
    if _accessible_document(connection, requester_id, document_id) is not None:
        raise ServiceError(409, "You already have access to this document.")

    reason = reason.strip()
    lowered_reason = reason.casefold()
    has_context = len(reason) >= 20
    suggestion = (
        "recommend_review"
        if has_context and any(word in lowered_reason for word in ("project", "work", "review", "case"))
        else "manual_review"
    )
    request_id = str(uuid.uuid4())
    try:
        with connection:
            connection.execute(
                """INSERT INTO access_requests
                   (id, document_id, requester_id, reason, suggestion, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (request_id, document_id, requester_id, reason, suggestion, utc_now()),
            )
            record_audit(
                connection,
                requester_id,
                "access_request.created",
                "access_request",
                request_id,
                document_id=document_id,
                suggestion=suggestion,
            )
    except sqlite3.IntegrityError as exception:
        if "unique" in str(exception).lower():
            raise ServiceError(409, "You already have a pending request for this document.") from exception
        raise

    return {
        "id": request_id,
        "document_id": document_id,
        "reason": reason,
        "suggestion": suggestion,
        "status": "pending",
        "message": "Suggestion is advisory only; document owners must approve access.",
    }


def list_access_requests(
    connection: sqlite3.Connection, user_id: int
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT ar.*, d.original_name, requester.email AS requester_email
           FROM access_requests ar
           JOIN documents d ON d.id = ar.document_id
           JOIN users requester ON requester.id = ar.requester_id
           WHERE d.owner_id = ? OR ar.requester_id = ?
           ORDER BY ar.created_at DESC""",
        (user_id, user_id),
    ).fetchall()
    return [{
        "id": row["id"],
        "document_id": row["document_id"],
        "filename": row["original_name"],
        "requester_id": row["requester_id"],
        "requester_email": row["requester_email"],
        "reason": row["reason"],
        "suggestion": row["suggestion"],
        "status": row["status"],
        "created_at": row["created_at"],
    } for row in rows]


def review_access_request(
    connection: sqlite3.Connection, owner_id: int, request_id: str, *, approve: bool
) -> dict[str, str]:
    with connection:
        row = connection.execute(
            """SELECT ar.*, d.owner_id FROM access_requests ar
               JOIN documents d ON d.id = ar.document_id WHERE ar.id = ?""",
            (request_id,),
        ).fetchone()
        if row is None or row["owner_id"] != owner_id:
            raise ServiceError(404, "Access request not found.")
        if row["status"] != "pending":
            raise ServiceError(409, "Access request has already been reviewed.")

        status = "approved" if approve else "rejected"
        reviewed_at = utc_now()
        cursor = connection.execute(
            """UPDATE access_requests SET status = ?, reviewed_at = ?
               WHERE id = ? AND status = 'pending'""",
            (status, reviewed_at, request_id),
        )
        if cursor.rowcount != 1:
            raise ServiceError(409, "Access request has already been reviewed.")
        if approve:
            connection.execute(
                """INSERT INTO document_grants (document_id, user_id, request_id, created_at)
                   VALUES (?, ?, ?, ?)""",
                (row["document_id"], row["requester_id"], request_id, reviewed_at),
            )
        record_audit(
            connection,
            owner_id,
            f"access_request.{status}",
            "access_request",
            request_id,
            document_id=row["document_id"],
            requester_id=row["requester_id"],
        )
    return {"id": request_id, "status": status}


def list_audit_events(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT id, actor_id, action, resource_type, resource_id, details, created_at
           FROM audit_log ORDER BY id DESC LIMIT 500"""
    ).fetchall()
    return [{
        "id": row["id"],
        "actor_id": row["actor_id"],
        "action": row["action"],
        "resource_type": row["resource_type"],
        "resource_id": row["resource_id"],
        "details": json.loads(row["details"]),
        "created_at": row["created_at"],
    } for row in rows]
