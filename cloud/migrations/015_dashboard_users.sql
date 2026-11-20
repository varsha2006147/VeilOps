-- Dashboard sign-in (control plane). Passwords are Argon2id hashes; tokens are short-lived JWTs.
CREATE TABLE IF NOT EXISTS dashboard_users (
    user_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);
-- Read before any tenant is known (like memberships); holds no telemetry.
GRANT SELECT, UPDATE ON dashboard_users TO veilops_app;
