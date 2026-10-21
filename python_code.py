from __future__ import annotations

import ipaddress
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar, cast

import click
from flask import Flask, g, jsonify, render_template, request, send_file

import functions

F = TypeVar("F", bound=Callable[..., Any])


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        JWT_SECRET_KEY=(
            os.environ.get("TRUST_VAULT_JWT_SECRET_KEY")
            or os.environ.get("TRUST_VAULT_SECRET_KEY")
            or secrets.token_hex(32)
        ),
        JWT_ISSUER="trust-vault",
        JWT_AUDIENCE="trust-vault-api",
        ACCESS_TOKEN_TTL_SECONDS=900,
        DATABASE=os.environ.get(
            "TRUST_VAULT_DATABASE",
            str(Path(app.instance_path) / "trust_vault.sqlite3"),
        ),
        UPLOAD_FOLDER=os.environ.get(
            "TRUST_VAULT_UPLOAD_FOLDER",
            str(Path(app.instance_path) / "uploads"),
        ),
        MAX_CONTENT_LENGTH=functions.MAX_UPLOAD_BYTES,
    )
    if test_config:
        app.config.update(test_config)
    key_value = app.config["JWT_SECRET_KEY"]
    if not isinstance(key_value, str) or len(key_value.encode("utf-8")) < 32:
        raise RuntimeError("JWT_SECRET_KEY must be at least 32 bytes.")

    if os.environ.get("TRUST_VAULT_ENV") == "production" and not (
        os.environ.get("TRUST_VAULT_JWT_SECRET_KEY") or os.environ.get("TRUST_VAULT_SECRET_KEY")
    ):
        raise RuntimeError("Set TRUST_VAULT_JWT_SECRET_KEY in production.")

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    functions.initialize_database(app.config["DATABASE"])

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = functions.connect_database(app.config["DATABASE"])
        return cast(sqlite3.Connection, g.db)

    def error_response(message: str, status: int):
        return jsonify(error=message), status

    def login_required(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            if g.user is None:
                return error_response("Authentication required.", 401)
            return view(*args, **kwargs)

        return cast(F, wrapped)

    def permission_required(permission: str) -> Callable[[F], F]:
        def decorate(view: F) -> F:
            @wraps(view)
            @login_required
            def wrapped(*args: Any, **kwargs: Any):
                if not functions.user_has_permission(
                    get_db(), g.user["id"], permission
                ):
                    return error_response(
                        f"Permission required: {permission}.", 403
                    )
                return view(*args, **kwargs)

            return cast(F, wrapped)

        return decorate

    def service_response(operation: Callable[[], Any], status: int = 200):
        try:
            result = operation()
        except functions.ServiceError as exception:
            return error_response(exception.message, exception.status_code)
        return jsonify(result), status

    @app.teardown_appcontext
    def teardown_db(_error: BaseException | None) -> None:
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.before_request
    def load_user_from_access_token() -> None:
        g.auth_token_id = None
        g.user = None
        if request.endpoint in {"health", "register", "login", "bootstrap_admin"}:
            return

        authorization = request.headers.get("Authorization", "")
        if not authorization:
            return

        scheme, separator, token = authorization.partition(" ")
        if scheme.casefold() != "bearer" or not separator or not token.strip():
            raise functions.ServiceError(401, "Use a valid Bearer access token.")
        g.user, g.auth_token_id = functions.authenticate_access_token(
            get_db(),
            token.strip(),
            app.config["JWT_SECRET_KEY"],
            app.config["JWT_ISSUER"],
            app.config["JWT_AUDIENCE"],
        )

    @app.errorhandler(functions.ServiceError)
    def service_error(exception: functions.ServiceError):
        return error_response(exception.message, exception.status_code)

    @app.errorhandler(403)
    def forbidden(_exception):
        return error_response("Forbidden.", 403)

    @app.errorhandler(404)
    def not_found(_exception):
        return error_response("Not found.", 404)

    @app.errorhandler(413)
    def too_large(_exception):
        return error_response("Upload exceeds the 16 MiB limit.", 413)

    @app.errorhandler(405)
    def method_not_allowed(_exception):
        return error_response("Method not allowed.", 405)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.post("/api/auth/register")
    def register():
        def operation():
            user = functions.register_user(get_db(), request.get_json(silent=True))
            return {"user": user}

        return service_response(operation, 201)

    @app.post("/api/auth/bootstrap-admin")
    def bootstrap_admin():
        try:
            is_loopback = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            return error_response("Administrator setup is only available from localhost.", 403)

        return service_response(
            lambda: {
                "user": functions.bootstrap_admin(
                    get_db(), request.get_json(silent=True)
                )
            },
            201,
        )

    @app.post("/api/auth/login")
    def login():
        def operation():
            user = functions.authenticate_user(get_db(), request.get_json(silent=True))
            access_token = functions.issue_access_token(
                get_db(),
                user,
                app.config["JWT_SECRET_KEY"],
                app.config["JWT_ISSUER"],
                app.config["JWT_AUDIENCE"],
                app.config["ACCESS_TOKEN_TTL_SECONDS"],
            )
            return {
                "user": user,
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": app.config["ACCESS_TOKEN_TTL_SECONDS"],
            }

        return service_response(operation)

    @app.post("/api/auth/logout")
    @permission_required("auth.logout")
    def logout():
        def operation():
            user_id = g.user["id"]
            role = g.user["role"]
            functions.logout_user(
                get_db(), user_id, getattr(g, "auth_token_id", None)
            )
            return {
                "message": "Logged out successfully!!!!.",
                "user_id": user_id,
                "role": role,
            }

        return service_response(operation)

    @app.get("/api/auth/me")
    @permission_required("auth.profile")
    def current_user():
        return jsonify(user=functions.public_user(
            g.user, functions.get_user_permissions(get_db(), g.user["id"])
        ))

    @app.put("/api/auth/credentials")
    @permission_required("auth.profile")
    def update_credentials():
        return service_response(
            lambda: {
                "user": functions.update_user_credentials(
                    get_db(), g.user["id"], request.get_json(silent=True)
                )
            }
        )

    @app.post("/api/admin/users")
    @permission_required("roles.manage")
    def create_user():
        return service_response(
            lambda: {
                "user": functions.create_user_by_admin(
                    get_db(), g.user["id"], request.get_json(silent=True)
                )
            },
            201,
        )

    @app.post("/api/admin/users/<int:user_id>/role")
    @permission_required("roles.manage")
    def set_user_role(user_id: int):
        return service_response(
            lambda: {
                "user": functions.set_user_role(
                    get_db(), g.user["id"], user_id, request.get_json(silent=True)
                )
            }
        )

    @app.get("/api/admin/users/<int:user_id>")
    @permission_required("roles.manage")
    def get_admin_user(user_id: int):
        return service_response(
            lambda: {
                "user": functions.get_user_permission_settings(get_db(), user_id)
            }
        )

    @app.put("/api/admin/users/<int:user_id>/permissions")
    @permission_required("roles.manage")
    def set_user_permissions(user_id: int):
        return service_response(
            lambda: {
                "user": functions.set_user_permissions(
                    get_db(), g.user["id"], user_id, request.get_json(silent=True)
                )
            }
        )

    @app.get("/api/admin/permissions")
    @permission_required("roles.manage")
    def get_permissions():
        return jsonify(permissions=functions.list_permissions(get_db()))

    @app.get("/api/admin/roles")
    @permission_required("roles.manage")
    def list_roles():
        return jsonify(roles=functions.list_roles(get_db()))

    @app.post("/api/admin/roles")
    @permission_required("roles.manage")
    def create_role():
        return service_response(
            lambda: {
                "role": functions.create_role(
                    get_db(), g.user["id"], request.get_json(silent=True)
                )
            },
            201,
        )

    @app.put("/api/admin/roles/<int:role_id>/permissions")
    @permission_required("roles.manage")
    def update_role_permissions(role_id: int):
        return service_response(
            lambda: {
                "role": functions.set_role_permissions(
                    get_db(), g.user["id"], role_id, request.get_json(silent=True)
                )
            }
        )

    @app.post("/api/documents")
    @permission_required("documents.upload")
    def upload_document():
        uploaded = request.files.get("file")
        if uploaded is None:
            return error_response("Provide a file in the 'file' field.", 400)
        return service_response(
            lambda: {
                "document": functions.upload_document(
                    get_db(),
                    g.user["id"],
                    uploaded.filename,
                    uploaded.stream,
                    app.config["UPLOAD_FOLDER"],
                )
            },
            201,
        )

    @app.get("/api/documents")
    @permission_required("documents.list")
    def list_documents():
        return jsonify(documents=functions.list_documents(get_db(), g.user["id"]))

    @app.get("/api/documents/<document_id>")
    @permission_required("documents.read")
    def get_document(document_id: str):
        return service_response(
            lambda: {"document": functions.get_accessible_document(
                get_db(), g.user["id"], document_id
            )}
        )

    @app.get("/api/documents/<document_id>/download")
    @permission_required("documents.download")
    def download_document(document_id: str):
        try:
            path, filename = functions.get_download(
                get_db(), g.user["id"], document_id, app.config["UPLOAD_FOLDER"]
            )
        except functions.ServiceError as exception:
            return error_response(exception.message, exception.status_code)
        return send_file(path, as_attachment=True, download_name=filename)

    @app.post("/api/documents/<document_id>/access-requests")
    @permission_required("access_requests.create")
    def create_access_request(document_id: str):
        return service_response(
            lambda: {"access_request": functions.create_access_request(
                get_db(), g.user["id"], document_id, request.get_json(silent=True)
            )},
            201,
        )

    @app.get("/api/access-requests")
    @permission_required("access_requests.list")
    def list_access_requests():
        return jsonify(access_requests=functions.list_access_requests(get_db(), g.user["id"]))

    @app.post("/api/access-requests/<request_id>/approve")
    @permission_required("access_requests.review")
    def approve_access_request(request_id: str):
        return service_response(
            lambda: {"access_request": functions.review_access_request(
                get_db(), g.user["id"], request_id, approve=True
            )}
        )

    @app.post("/api/access-requests/<request_id>/reject")
    @permission_required("access_requests.review")
    def reject_access_request(request_id: str):
        return service_response(
            lambda: {"access_request": functions.review_access_request(
                get_db(), g.user["id"], request_id, approve=False
            )}
        )

    @app.get("/api/admin/audit-log")
    @permission_required("audit.read")
    def audit_log():
        return jsonify(events=functions.list_audit_events(get_db()))

    @app.cli.command("promote-admin")
    @click.argument("email")
    def promote_admin(email: str) -> None:
        """Promote an account from the trusted local command line."""
        try:
            functions.promote_admin(app.config["DATABASE"], email)
        except functions.ServiceError as exception:
            raise click.ClickException(exception.message) from exception
        click.echo(f"Administrator role granted to {email.strip().casefold()}.")

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=False)
