DROP INDEX IF EXISTS auth.idx_users_email_unique;
DROP INDEX IF EXISTS auth.idx_users_account_unique;

ALTER TABLE auth.users ADD CONSTRAINT users_email_account_key UNIQUE (email, account);
