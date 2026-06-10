-- Identity invariants: email and account must each be unique on their own.
--
-- The original schema only had UNIQUE(email, account) — a composite
-- constraint — which allowed two users to register with the same email under
-- different account names. Login and password reset both look users up by
-- email alone, so duplicate emails break authentication.

-- Normalize existing emails first so case-variant duplicates surface as
-- conflicts when the unique index is created below. If this migration fails
-- here or on index creation, duplicate identities already exist and must be
-- resolved manually before re-running.
UPDATE auth.users SET email = lower(email) WHERE email <> lower(email);

ALTER TABLE auth.users DROP CONSTRAINT IF EXISTS users_email_account_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON auth.users (lower(email));
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_account_unique ON auth.users (account);
