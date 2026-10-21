# Trust Vault API

Base URL: `http://127.0.0.1:5000`. Register and login are public endpoints.
Login returns a signed JWT access token. All other protected endpoints require
`Authorization: Bearer <access_token>`. There is no CSRF token or session-cookie
authentication.

Flask routes are in `python_code.py`. Database and application logic are in
`functions.py`.

## Register, log in, and authenticate

1. `POST /api/auth/register` with JSON email and password. Registration creates
   a regular user with the built-in `user` role and does not log in.
2. `POST /api/auth/login` with the same credentials.
3. Copy `access_token` from the response.
4. In Postman, select **Authorization → Bearer Token** for protected requests
   and paste the token.
5. Access tokens expire after 15 minutes. Log in again to get a new token.

For local development, create the first administrator with
`POST /api/auth/bootstrap-admin`. It accepts requests only from localhost,
works only before an administrator exists, and either creates the admin
account or promotes an existing account after verifying its password. It
returns `409` after admin setup has already been completed.

To change credentials for an account you can already log in to, send
`PUT /api/auth/credentials` with that account's bearer token and its current
password. The request updates the email and password and revokes all existing
access tokens for that account; log in again using the new credentials.

Example login response:

```json
{
  "user": {
    "id": 1,
    "email": "alice@example.com",
    "role": "user",
    "permissions": ["documents.list", "documents.read"]
  },
  "access_token": "<signed-jwt>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

Protected endpoints require the user's effective permissions: their assigned
role's permissions unless an administrator has set a per-user override.
Permission and role changes take effect on the next request; they are not
trusted from JWT claims. Configure `TRUST_VAULT_JWT_SECRET_KEY`
to a stable random value of at least 32 bytes and use HTTPS in production.

Logout requires the Bearer token and no request body. It revokes the token:

```json
{
  "message": "Logged out.",
  "user_id": 1,
  "role": "user"
}
```

## Role and permission administration

Only a user whose effective permissions include `roles.manage` can use
`/api/admin/roles`, `/api/admin/permissions`, user creation, role assignment,
and per-user permission endpoints.

An administrator can create an account and assign its role in one request:

`POST /api/admin/users`

```json
{
  "email": "new-user@example.com",
  "password": "a-long-unique-password",
  "role_id": 3
}
```

`role_id` is optional; when omitted, the new account receives the built-in
`user` role. Password requirements match public registration. Admin-created
accounts may also include an optional `permissions` list to set an exact
per-user override. When omitted, the account inherits permissions from its
role. Public registration does not accept permission assignments. The created
user must log in separately to receive their own JWT.

Set or replace a user's exact permission set:

`PUT /api/admin/users/{user_id}/permissions`

```json
{
  "permissions": ["auth.profile", "documents.list"]
}
```

An empty list grants no permissions. To remove the override and inherit from
the assigned role again, send:

```json
{
  "inherit_role": true
}
```

Only known permission names are accepted. Effective permissions are returned
by login and `GET /api/auth/me` and are checked on every protected request.

1. List the permission catalog with `GET /api/admin/permissions`.
2. Create a role:

   `POST /api/admin/roles`

   ```json
   {
     "name": "reviewer",
     "description": "Can list and read shared documents"
   }
   ```

   Role names are lowercase and 2-50 characters, starting with a letter and
   containing only letters, digits, `_`, or `-`.
3. Configure the role's complete permission set:

   `PUT /api/admin/roles/{role_id}/permissions`

   ```json
   {
     "permissions": [
       "auth.profile",
       "auth.logout",
       "documents.list",
       "documents.read",
       "documents.download"
     ]
   }
   ```

   This replaces the role's entire permission set. Every permission name must
   exist in the catalog.
4. Assign the role:

   `POST /api/admin/users/{user_id}/role`

   ```json
   {
     "role_id": 3
   }
   ```

5. Check `GET /api/auth/me` using that user's token to see the role and
   effective permissions.

`GET /api/admin/roles` lists roles and their permissions. The built-in `admin`
role must retain `roles.manage` to avoid losing administrative access.
Registration never allows the caller to choose a role. The first administrator
can be created through the localhost-only setup endpoint above or promoted
using the trusted local CLI command documented in `README.md`.

Permission catalog:

| Permission | Allows |
|---|---|
| `auth.profile` | Read the current account profile |
| `auth.logout` | Revoke current token and log out |
| `documents.upload` | Upload documents |
| `documents.list` | List owned/shared documents |
| `documents.read` | Read accessible document metadata |
| `documents.download` | Download accessible documents |
| `access_requests.create` | Request document access |
| `access_requests.list` | List visible access requests |
| `access_requests.review` | Approve/reject requests for owned documents |
| `roles.manage` | List/create roles, configure permissions, assign roles |
| `audit.read` | Read the audit log |

Role permissions authorize an operation; document ownership or an explicit
owner-approved grant is still required to access a particular document.

## Endpoints

| Method | Path | Permission | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | Public | Liveness check |
| `POST` | `/api/auth/register` | Public | Create a regular user |
| `PUT` | `/api/auth/credentials` | `auth.profile` | Change own email/password after current-password verification |
| `POST` | `/api/auth/login` | Public | Verify credentials and return a JWT |
| `POST` | `/api/auth/logout` | `auth.logout` | Revoke token |
| `GET` | `/api/auth/me` | `auth.profile` | Get profile and effective permissions |
| `GET` | `/api/admin/permissions` | `roles.manage` | List permission catalog |
| `GET` | `/api/admin/roles` | `roles.manage` | List roles and permissions |
| `POST` | `/api/admin/roles` | `roles.manage` | Create a role |
| `PUT` | `/api/admin/roles/{role_id}/permissions` | `roles.manage` | Replace role permissions |
| `POST` | `/api/admin/users` | `roles.manage` | Create an account, optionally with role and permission overrides |
| `GET` | `/api/admin/users/{user_id}` | `roles.manage` | Read a user's effective permissions and inheritance state |
| `POST` | `/api/admin/users/{user_id}/role` | `roles.manage` | Assign a role by `role_id` |
| `PUT` | `/api/admin/users/{user_id}/permissions` | `roles.manage` | Set exact permissions or restore role inheritance |
| `POST` | `/api/documents` | `documents.upload` | Upload multipart field `file` |
| `GET` | `/api/documents` | `documents.list` | List owned/shared documents |
| `GET` | `/api/documents/{document_id}` | `documents.read` | Read accessible metadata |
| `GET` | `/api/documents/{document_id}/download` | `documents.download` | Download accessible document |
| `POST` | `/api/documents/{document_id}/access-requests` | `access_requests.create` | Request document access |
| `GET` | `/api/access-requests` | `access_requests.list` | List visible access requests |
| `POST` | `/api/access-requests/{request_id}/approve` | `access_requests.review` | Owner approves request |
| `POST` | `/api/access-requests/{request_id}/reject` | `access_requests.review` | Owner rejects request |
| `GET` | `/api/admin/audit-log` | `audit.read` | Read latest 500 audit events |

Uploads are limited to 16 MiB and extensions `doc`, `docx`, `jpeg`, `jpg`,
`pdf`, `png`, and `txt`. Stored filenames are server-generated.

Access suggestions are deterministic local heuristics, not an external AI
model. Suggestions are advisory and never grant permission automatically.

## Status codes

Common responses include `201` for creation, `400` for invalid input, `401`
for missing/invalid token or invalid credentials, `403` for missing
permissions, `404` for inaccessible resources, `409` for duplicate/conflicting
changes, `413` for oversized uploads, and `415` for unsupported file types.
