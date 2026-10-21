# Trust Vault

A Flask API for private document storage, owner-approved sharing, roles, and
audit logging.

## Code layout

- `python_code.py` contains Flask setup, request authentication, route
  declarations, and HTTP response handling.
- `functions.py` contains database setup, validation, account/document
  operations, permission checks, access-request workflows, and audit services.
- `templates/index.html` and `static/` contain the browser dashboard served by
  the Flask app.
- `tests/test_api.py` exercises API behavior and private-document access rules.

## Run locally

Python 3.10 or newer is required. From the project directory, create and
activate a virtual environment, then install dependencies:

```powershell
py -m venv env
.\env\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the API:

```powershell
python python_code.py
```

The API listens on `http://127.0.0.1:5000`. Data is stored under the Flask
instance directory by default. Set `TRUST_VAULT_DATABASE` and
`TRUST_VAULT_UPLOAD_FOLDER` to change those locations. For deployment, set a
stable, random `TRUST_VAULT_JWT_SECRET_KEY` of at least 32 bytes and serve
traffic over HTTPS. Changing the key invalidates outstanding access tokens.

Open `http://127.0.0.1:5000` in a browser to use the dashboard. It supports
local first-admin setup, login/registration, role and permission setup, user
creation and role assignment, document upload/list/download, access-request
review, and logout. Access tokens remain in browser memory and are cleared on
logout or page reload. While signed in, document and access-request lists
refresh every 15 seconds when the dashboard tab is visible; changed role
permissions are reloaded automatically.

## Authentication flow

1. Register using `POST /api/auth/register` with JSON email and password.
   Registration does not log in automatically.
2. Log in using `POST /api/auth/login` with the same credentials.
3. Copy `access_token` from the response.
4. For all protected API calls, use
   `Authorization: Bearer <access_token>`.
5. Tokens expire after 15 minutes. Log in again to receive another token.

No CSRF token or session cookie is needed. See [API.md](API.md) for the
Postman/API flow and [THREAT_MODEL.md](THREAT_MODEL.md) before exposing an
instance to a network.

## Roles and permissions

The built-in `user` role is assigned at registration and receives normal
document/access-request permissions. The `admin` role receives the full
permission catalog. Only a caller with `roles.manage` can create custom roles,
replace their permission sets, or assign a role to a user. Role permission
changes are checked from the database on each API request and therefore apply
without waiting for a new JWT.

An administrator can create users from `POST /api/admin/users`, optionally
assigning an existing role with `role_id`. If omitted, the account receives
the default `user` role. The new account logs in with its own credentials to
get a JWT.

To create the first administrator during local development, send a
`POST /api/auth/bootstrap-admin` request to `http://127.0.0.1:5000` from
Postman. The endpoint is restricted to localhost and can only be used before
an administrator exists. It creates a new administrator or promotes an
existing account after verifying that account's password. Alternatively,
promote an account from the trusted machine running the app:

```powershell
flask --app python_code:app promote-admin admin@example.com
```

Registration never accepts a role field. The built-in administrator role must
retain `roles.manage` and the last administrator cannot be demoted. See
[API.md](API.md) for the permission catalog and role-management request
examples.

## Tests

Run the API and permission tests:

```powershell
python -m unittest discover -s tests -v
```

## Current scope

Access suggestions are transparent local heuristics, not an external AI model.
They never grant permissions: only the document owner can approve a pending
request. Deployment, hosted-provider configuration, live testing, demo
credentials, and a demo video remain environment-specific follow-up work.
