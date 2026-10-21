# Trust Vault threat notes

## Assets and boundaries

The application handles account credentials, JWT access tokens, private
document bytes, document metadata, access approvals, and audit events. Trust boundaries
include the network client, Flask application process, SQLite database, and
local upload directory. This starter is designed for local development and
requires additional operational hardening before public deployment.

## Implemented controls

- Passwords are stored as Werkzeug password hashes, not plaintext.
- Login returns a signed, 15-minute HS256 JWT access token. Tokens are checked
  against fixed issuer, audience, and algorithm values, and logout revokes the
  token identifier in SQLite. Protected handlers load the current user and
  role from the database rather than trusting role claims in the token.
- All protected API routes require an explicit Bearer token; API authentication
  does not use ambient browser cookies or CSRF tokens.
- Registration and login are public credential-based API endpoints. Successful
  login issues the token; registration does not create an authenticated session.
- Roles and permissions are stored relationally. Each route checks its required
  permission against the user's current database role on every request; role
  changes do not depend on trusting JWT role/permission claims.
- Registration always assigns the least-privileged default role. Administrator
  promotion is restricted to a local CLI command; role administration requires
  the `roles.manage` permission. The built-in admin role must retain that
  permission.
- Document listing, metadata, and downloads query for ownership or an explicit
  owner-approved grant. Unauthorized and nonexistent documents return the
  same 404 response.
- Upload types and size are restricted. Client paths are never used for the
  stored path; payload names are server-generated.
- Access suggestions cannot create grants. Only the document owner can approve
  or reject a pending request.
- Sensitive events, including login outcomes, document operations, role
  changes, and request review, are written to the SQLite audit log.
- SQL statements use bound parameters.

## Important limitations and mitigations before production

- **No rate limiting or account recovery:** add throttling, monitoring, and a
  verified recovery workflow before Internet exposure.
- **Access-token lifecycle:** access tokens last 15 minutes and there is no
  refresh-token endpoint. Set a stable, high-entropy JWT signing secret; token
  revocation depends on the SQLite database being available.
- **Local filesystem and SQLite:** use durable private storage, encrypted
  backups, least-privilege filesystem permissions, retention rules, and a
  production database appropriate to the deployment.
- **No malware scanning or content inspection:** scan uploads, consider MIME
  and file-signature verification, and serve downloads only as attachments.
- **No external AI integration:** suggestions are simple local heuristics. If a
  model is added, minimize/redact submitted data, protect provider credentials,
  log only appropriate metadata, and keep authorization decisions with a human.
- **Audit log is application-managed:** protect it from modification by
  application operators, define retention and export procedures, and avoid
  recording secrets or document contents.
- **Deployment remains unverified:** configure secret management, HTTPS,
  backups, monitoring, and access controls; then run
  security and privacy tests against the hosted service.
- **Single-process starter:** test concurrency, database migrations, storage
  failure handling, and operational recovery before scaling.

## Security test focus

`tests/test_api.py` checks that a second user cannot list, inspect, or download
another user's private document; that a requester cannot approve their own
request; and that access works only after the owner approves. Extend these
tests for rejected requests, guessed identifiers, administrator boundaries,
missing/invalid tokens, malformed uploads, and deployment configuration as the API
evolves.
