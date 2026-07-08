DROP INDEX IF EXISTS auth.idx_users_role;

ALTER TABLE auth.users
DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE auth.users
DROP COLUMN IF EXISTS role;
