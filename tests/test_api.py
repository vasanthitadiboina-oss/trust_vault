import io
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

import functions
from python_code import create_app


class TrustVaultApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-key-for-unit-tests-32-bytes",
            "DATABASE": str(root / "test.sqlite3"),
            "UPLOAD_FOLDER": str(root / "uploads"),
        })
        self.owner = self.app.test_client()
        self.other = self.app.test_client()
        self.owner_id = self.register(self.owner, "owner@example.com")
        self.other_id = self.register(self.other, "other@example.com")
        self.owner_headers = self.login(self.owner, "owner@example.com")
        self.other_headers = self.login(self.other, "other@example.com")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dashboard_serves_frontend_assets(self):
        response = self.app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Trust Vault", response.data)
        self.assertIn(b"/static/styles.css", response.data)
        self.assertIn(b"/static/app.js", response.data)
        self.assertIn(b"dashboard-heading", response.data)
        self.assertIn(b"document-search", response.data)

    def register(self, client, email):
        response = client.post(
            "/api/auth/register",
            json={"email": email, "password": "correct horse battery staple"},
        )
        self.assertEqual(response.status_code, 201)
        return response.json["user"]["id"]

    def login(self, client, email):
        response = client.post(
            "/api/auth/login",
            json={"email": email, "password": "correct horse battery staple"},
        )
        self.assertEqual(response.status_code, 200)
        return {"Authorization": f"Bearer {response.json['access_token']}"}

    def upload(self, client, headers, filename="private.pdf", content=b"private document"):
        return client.post(
            "/api/documents",
            data={"file": (io.BytesIO(content), filename)},
            headers=headers,
            content_type="multipart/form-data",
        )

    def test_private_documents_are_not_listed_or_read_by_another_user(self):
        self.assertEqual(self.app.test_client().get("/api/documents").status_code, 401)
        uploaded = self.upload(self.owner, self.owner_headers)
        self.assertEqual(uploaded.status_code, 201)
        document_id = uploaded.json["document"]["id"]

        self.assertEqual(
            self.other.get("/api/documents", headers=self.other_headers).json["documents"], []
        )
        self.assertEqual(
            self.other.get(
                f"/api/documents/{document_id}", headers=self.other_headers
            ).status_code,
            404,
        )
        denied_download = self.other.get(
            f"/api/documents/{document_id}/download", headers=self.other_headers
        )
        self.assertEqual(denied_download.status_code, 404)

    def test_access_requires_request_and_owner_approval(self):
        uploaded = self.upload(self.owner, self.owner_headers)
        document_id = uploaded.json["document"]["id"]
        request_response = self.other.post(
            f"/api/documents/{document_id}/access-requests",
            json={"reason": "I need this for the project review."},
            headers=self.other_headers,
        )
        self.assertEqual(request_response.status_code, 201)
        access_request = request_response.json["access_request"]
        self.assertEqual(access_request["status"], "pending")
        self.assertIn(access_request["suggestion"], {"recommend_review", "manual_review"})
        duplicate_request = self.other.post(
            f"/api/documents/{document_id}/access-requests",
            json={"reason": "I need this for the project review."},
            headers=self.other_headers,
        )
        self.assertEqual(duplicate_request.status_code, 409)

        self.assertEqual(
            self.other.get(
                f"/api/documents/{document_id}/download", headers=self.other_headers
            ).status_code,
            404,
        )
        request_id = access_request["id"]
        self.assertEqual(
            self.other.post(
                f"/api/access-requests/{request_id}/approve",
                headers=self.other_headers,
            ).status_code,
            404,
        )
        approved = self.owner.post(
            f"/api/access-requests/{request_id}/approve",
            headers=self.owner_headers,
        )
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json["access_request"]["status"], "approved")

        downloaded = self.other.get(
            f"/api/documents/{document_id}/download", headers=self.other_headers
        )
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.data, b"private document")
        downloaded.close()
        self.assertEqual(
            self.other.get("/api/documents", headers=self.other_headers).json["documents"][0]["id"],
            document_id,
        )

    def test_roles_are_not_self_assignable_and_admin_changes_are_audited(self):
        self.assertEqual(
            self.other.post(
                f"/api/admin/users/{self.owner_id}/role",
                json={"role": "admin"},
                headers=self.other_headers,
            ).status_code,
            403,
        )
        with closing(sqlite3.connect(self.app.config["DATABASE"])) as db:
            with db:
                db.execute(
                    """UPDATE users SET role = 'admin',
                       role_id = (SELECT id FROM roles WHERE name = 'admin')
                       WHERE id = ?""",
                    (self.owner_id,),
                )

        self.assertEqual(
            self.owner.post(
                f"/api/admin/users/{self.owner_id}/role",
                json={"role": "user"},
                headers=self.owner_headers,
            ).status_code,
            409,
        )
        self.assertEqual(
            self.owner.post(
                f"/api/admin/users/{self.other_id}/role",
                json={"role": "admin"},
                headers=self.owner_headers,
            ).status_code,
            200,
        )
        events = self.owner.get("/api/admin/audit-log", headers=self.owner_headers)
        self.assertEqual(events.status_code, 200)
        self.assertIn("user.role_changed", [event["action"] for event in events.json["events"]])

    def test_localhost_bootstrap_promotes_existing_account_only_once(self):
        response = self.owner.post(
            "/api/auth/bootstrap-admin",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["user"]["role"], "admin")
        self.assertIn("roles.manage", response.json["user"]["permissions"])

        repeated = self.owner.post(
            "/api/auth/bootstrap-admin",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(repeated.status_code, 409)

    def test_localhost_bootstrap_creates_new_admin_account(self):
        response = self.owner.post(
            "/api/auth/bootstrap-admin",
            json={
                "email": "first-admin@example.com",
                "password": "a-secure-admin-password",
            },
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["user"]["role"], "admin")

        login = self.owner.post(
            "/api/auth/login",
            json={
                "email": "first-admin@example.com",
                "password": "a-secure-admin-password",
            },
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json["user"]["role"], "admin")

    def test_admin_bootstrap_rejects_non_local_requests(self):
        response = self.app.test_client().post(
            "/api/auth/bootstrap-admin",
            json={
                "email": "new-admin@example.com",
                "password": "correct horse battery staple",
            },
            environ_base={"REMOTE_ADDR": "203.0.113.5"},
        )
        self.assertEqual(response.status_code, 403)

    def test_admin_can_create_role_grant_permission_and_assign_user(self):
        promoted = self.owner.post(
            "/api/auth/bootstrap-admin",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(promoted.status_code, 201)

        catalog = self.owner.get("/api/admin/permissions", headers=self.owner_headers)
        self.assertEqual(catalog.status_code, 200)
        permission_names = {item["name"] for item in catalog.json["permissions"]}
        self.assertIn("documents.list", permission_names)
        self.assertIn("documents.upload", permission_names)

        created = self.owner.post(
            "/api/admin/roles",
            json={"name": "viewer", "description": "Read-only document access"},
            headers=self.owner_headers,
        )
        self.assertEqual(created.status_code, 201)
        role = created.json["role"]
        self.assertEqual(role["name"], "viewer")

        configured = self.owner.put(
            f"/api/admin/roles/{role['id']}/permissions",
            json={"permissions": ["auth.profile", "documents.list"]},
            headers=self.owner_headers,
        )
        self.assertEqual(configured.status_code, 200)
        self.assertEqual(
            set(configured.json["role"]["permissions"]),
            {"auth.profile", "documents.list"},
        )

        assigned = self.owner.post(
            f"/api/admin/users/{self.other_id}/role",
            json={"role_id": role["id"]},
            headers=self.owner_headers,
        )
        self.assertEqual(assigned.status_code, 200)
        self.assertEqual(assigned.json["user"]["role"], "viewer")

        profile = self.other.get("/api/auth/me", headers=self.other_headers)
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.json["user"]["permissions"], ["auth.profile", "documents.list"])
        self.assertEqual(
            self.other.post(
                "/api/documents",
                data={"file": (io.BytesIO(b"no upload permission"), "private.txt")},
                headers=self.other_headers,
                content_type="multipart/form-data",
            ).status_code,
            403,
        )
        self.assertEqual(
            self.other.get("/api/documents", headers=self.other_headers).status_code,
            200,
        )
        self.assertEqual(
            self.other.get("/api/admin/roles", headers=self.other_headers).status_code,
            403,
        )
        unknown_permission = self.owner.put(
            f"/api/admin/roles/{role['id']}/permissions",
            json={"permissions": ["documents.superpower"]},
            headers=self.owner_headers,
        )
        self.assertEqual(unknown_permission.status_code, 400)

    def test_admin_can_create_user_with_selected_role(self):
        with closing(sqlite3.connect(self.app.config["DATABASE"])) as db:
            with db:
                db.execute(
                    """UPDATE users SET role = 'admin',
                       role_id = (SELECT id FROM roles WHERE name = 'admin')
                       WHERE id = ?""",
                    (self.owner_id,),
                )

        role_response = self.owner.post(
            "/api/admin/roles",
            json={"name": "upload_manager", "description": "Can upload and list files"},
            headers=self.owner_headers,
        )
        self.assertEqual(role_response.status_code, 201)
        role_id = role_response.json["role"]["id"]
        self.owner.put(
            f"/api/admin/roles/{role_id}/permissions",
            json={"permissions": ["auth.profile", "documents.list", "documents.upload"]},
            headers=self.owner_headers,
        )

        created = self.owner.post(
            "/api/admin/users",
            json={
                "email": "created-by-admin@example.com",
                "password": "a-unique-strong-password",
                "role_id": role_id,
            },
            headers=self.owner_headers,
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json["user"]["role_id"], role_id)
        self.assertEqual(created.json["user"]["role"], "upload_manager")
        self.assertEqual(
            set(created.json["user"]["permissions"]),
            {"auth.profile", "documents.list", "documents.upload"},
        )

        login = self.app.test_client().post(
            "/api/auth/login",
            json={
                "email": "created-by-admin@example.com",
                "password": "a-unique-strong-password",
            },
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json["user"]["role_id"], role_id)
        self.assertEqual(
            set(login.json["user"]["permissions"]),
            {"auth.profile", "documents.list", "documents.upload"},
        )

        self.assertEqual(
            self.other.post(
                "/api/admin/users",
                json={
                    "email": "not-an-admin@example.com",
                    "password": "a-unique-strong-password",
                    "role_id": role_id,
                },
                headers=self.other_headers,
            ).status_code,
            403,
        )

    def test_admin_can_assign_permissions_per_user_and_restore_role_defaults(self):
        with closing(sqlite3.connect(self.app.config["DATABASE"])) as db:
            with db:
                db.execute(
                    """UPDATE users SET role = 'admin',
                       role_id = (SELECT id FROM roles WHERE name = 'admin')
                       WHERE id = ?""",
                    (self.owner_id,),
                )

        admin_headers = self.owner_headers
        catalog = self.owner.get("/api/admin/permissions", headers=admin_headers)
        all_permissions = sorted(item["name"] for item in catalog.json["permissions"])

        limited_user = self.owner.post(
            "/api/admin/users",
            json={"email": "limited@example.com", "password": "a-unique-strong-password"},
            headers=admin_headers,
        )
        full_user = self.owner.post(
            "/api/admin/users",
            json={
                "email": "full@example.com",
                "password": "a-unique-strong-password",
                "permissions": all_permissions,
            },
            headers=admin_headers,
        )
        self.assertEqual(limited_user.status_code, 201)
        self.assertEqual(full_user.status_code, 201)

        limited_permissions = ["auth.profile", "documents.list"]
        limited_result = self.owner.put(
            f"/api/admin/users/{limited_user.json['user']['id']}/permissions",
            json={"permissions": limited_permissions},
            headers=admin_headers,
        )
        self.assertEqual(limited_result.status_code, 200)
        self.assertEqual(set(full_user.json["user"]["permissions"]), set(all_permissions))
        loaded_user = self.owner.get(
            f"/api/admin/users/{limited_user.json['user']['id']}",
            headers=admin_headers,
        )
        self.assertEqual(loaded_user.status_code, 200)
        self.assertFalse(loaded_user.json["user"]["inherits_role"])
        self.assertEqual(
            set(loaded_user.json["user"]["permissions"]),
            set(limited_permissions),
        )

        limited_login = self.app.test_client().post(
            "/api/auth/login",
            json={"email": "limited@example.com", "password": "a-unique-strong-password"},
        )
        full_login = self.app.test_client().post(
            "/api/auth/login",
            json={"email": "full@example.com", "password": "a-unique-strong-password"},
        )
        limited_headers = {"Authorization": f"Bearer {limited_login.json['access_token']}"}
        full_headers = {"Authorization": f"Bearer {full_login.json['access_token']}"}
        self.assertEqual(set(limited_login.json["user"]["permissions"]), set(limited_permissions))
        self.assertEqual(set(full_login.json["user"]["permissions"]), set(all_permissions))
        self.assertEqual(
            self.upload(self.app.test_client(), limited_headers).status_code,
            403,
        )
        self.assertEqual(
            self.upload(self.app.test_client(), full_headers).status_code,
            201,
        )

        inherited = self.owner.put(
            f"/api/admin/users/{limited_user.json['user']['id']}/permissions",
            json={"inherit_role": True},
            headers=admin_headers,
        )
        self.assertEqual(inherited.status_code, 200)
        roles = self.owner.get("/api/admin/roles", headers=admin_headers).json["roles"]
        default_permissions = next(
            set(role["permissions"]) for role in roles if role["name"] == "user"
        )
        self.assertEqual(
            set(inherited.json["user"]["permissions"]),
            default_permissions,
        )
        self.assertTrue(inherited.json["user"]["inherits_role"])

    def test_last_admin_cannot_lose_role_management_permission_override(self):
        with closing(sqlite3.connect(self.app.config["DATABASE"])) as db:
            with db:
                db.execute(
                    """UPDATE users SET role = 'admin',
                       role_id = (SELECT id FROM roles WHERE name = 'admin')
                       WHERE id = ?""",
                    (self.owner_id,),
                )

        response = self.owner.put(
            f"/api/admin/users/{self.owner_id}/permissions",
            json={"permissions": ["auth.profile", "auth.logout"]},
            headers=self.owner_headers,
        )
        self.assertEqual(response.status_code, 409)
        profile = self.owner.get("/api/auth/me", headers=self.owner_headers)
        self.assertIn("roles.manage", profile.json["user"]["permissions"])

    def test_existing_database_roles_are_migrated(self):
        database = str(Path(self.temp_dir.name) / "legacy.sqlite3")
        with closing(sqlite3.connect(database)) as db:
            with db:
                db.execute(
                    """CREATE TABLE users (
                       id INTEGER PRIMARY KEY,
                       email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                       password_hash TEXT NOT NULL,
                       role TEXT NOT NULL DEFAULT 'user'
                           CHECK (role IN ('user', 'admin')),
                       created_at TEXT NOT NULL
                    )"""
                )
                db.executemany(
                    """INSERT INTO users (email, password_hash, role, created_at)
                       VALUES (?, ?, ?, ?)""",
                    [
                        ("legacy-user@example.com", "hash", "user", "2026-01-01"),
                        ("legacy-admin@example.com", "hash", "admin", "2026-01-01"),
                    ],
                )

        functions.initialize_database(database)
        connection = functions.connect_database(database)
        try:
            user = functions.get_user_by_id(connection, 1)
            admin = functions.get_user_by_id(connection, 2)
            self.assertEqual(user["role"], "user")
            self.assertEqual(admin["role"], "admin")
            self.assertTrue(functions.user_has_permission(connection, 1, "documents.list"))
            self.assertTrue(functions.user_has_permission(connection, 2, "roles.manage"))
        finally:
            connection.close()

    def test_upload_validation_and_authentication(self):
        logout = self.other.post("/api/auth/logout", headers=self.other_headers)
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(self.other.get("/api/documents").status_code, 401)
        self.other_headers = self.login(self.other, "other@example.com")
        self.assertEqual(
            self.upload(self.other, self.other_headers, filename="malware.exe").status_code,
            415,
        )
        self.assertEqual(
            self.upload(
                self.other, self.other_headers, filename="empty.txt", content=b""
            ).status_code,
            400,
        )

    def test_login_returns_bearer_access_token_and_logout_revokes_it(self):
        login_client = self.app.test_client()
        response = login_client.post(
            "/api/auth/login",
            json={"email": "other@example.com", "password": "correct horse battery staple"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["token_type"], "Bearer")
        self.assertEqual(response.json["expires_in"], 900)
        token = response.json["access_token"]
        self.assertTrue(token)
        headers = {"Authorization": f"Bearer {token}"}

        token_client = self.app.test_client()
        current_user = token_client.get("/api/auth/me", headers=headers)
        self.assertEqual(current_user.status_code, 200)
        self.assertEqual(current_user.json["user"]["email"], "other@example.com")

        tampered_token = token[:-1] + ("a" if token[-1] != "a" else "b")
        tampered = self.app.test_client().get(
            "/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"}
        )
        self.assertEqual(tampered.status_code, 401)

        logout = token_client.post("/api/auth/logout", headers=headers)
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(logout.json["user_id"], self.other_id)
        self.assertEqual(logout.json["role"], "user")
        revoked = self.app.test_client().get("/api/auth/me", headers=headers)
        self.assertEqual(revoked.status_code, 401)

    def test_user_can_change_credentials_and_existing_tokens_are_revoked(self):
        response = self.owner.put(
            "/api/auth/credentials",
            json={
                "current_password": "correct horse battery staple",
                "email": "updated-owner@example.com",
                "password": "a-new-secure-password-123",
            },
            headers=self.owner_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["user"]["email"], "updated-owner@example.com")
        self.assertEqual(response.json["user"]["role"], "user")
        self.assertEqual(
            self.owner.get("/api/auth/me", headers=self.owner_headers).status_code,
            401,
        )

        login_client = self.app.test_client()
        old_login = login_client.post(
            "/api/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(old_login.status_code, 401)

        new_login = login_client.post(
            "/api/auth/login",
            json={
                "email": "updated-owner@example.com",
                "password": "a-new-secure-password-123",
            },
        )
        self.assertEqual(new_login.status_code, 200)

    def test_changing_credentials_requires_current_password(self):
        response = self.owner.put(
            "/api/auth/credentials",
            json={
                "current_password": "wrong-current-password",
                "email": "updated-owner@example.com",
                "password": "a-new-secure-password-123",
            },
            headers=self.owner_headers,
        )
        self.assertEqual(response.status_code, 401)

        login = self.app.test_client().post(
            "/api/auth/login",
            json={
                "email": "owner@example.com",
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(login.status_code, 200)


if __name__ == "__main__":
    unittest.main()
