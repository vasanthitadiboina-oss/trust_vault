# Development prompts and evidence

## Requested scope

Implement Trust Vault registration/login/logout and roles; document APIs and
access checks; privacy tests; access requests with owner approval and audit
logging; and API/threat documentation.

## Implementation record

- `python_code.py` contains Flask setup, JWT authentication, permission gates,
  route declarations, and HTTP response handling. `functions.py` contains
  database and application logic.
- Users receive the built-in least-privileged `user` role at registration.
  Administrators can create roles, grant permissions from a fixed catalog,
  create accounts with an optional role, and assign roles to accounts using
  protected management endpoints.
- Route authorization checks a permission against the user's current role in
  the database on every request. Login responses and `/api/auth/me` include
  the effective role and permissions; JWT claims are not the authority for
  role changes.
- Existing databases are migrated to the roles/permissions tables and existing
  `user`/`admin` assignments are retained.
- Registration/login need only JSON credentials. No CSRF token or session
  cookie is used. Other protected APIs require a JWT Bearer token.
- Tokens expire after 15 minutes and logout revokes the token. Login does not
  print submitted credentials.
- Document owner grants remain required even when a role has document-related
  permissions. Suggestions are advisory and never grant access.

## Verification evidence

Verification run in the project environment after admin user creation support:

```text
python -m unittest discover -s tests -v
Ran 8 tests in 12.812s
OK
```

The suite covers registration/login, missing/invalid JWTs, token revocation,
private-document isolation, owner approval, custom role creation/permission
assignment/user assignment, administrator-created users with a selected role,
route permission enforcement, and migration of an existing database. Python
syntax compilation succeeded for the application and test modules.

No hosted deployment, live-service test, demo account, or video has been
created.
