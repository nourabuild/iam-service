-- Remove the index on is_admin
DROP INDEX IF EXISTS auth.idx_users_is_admin;

-- Remove is_admin column from users table
ALTER TABLE auth.users
DROP COLUMN IF EXISTS is_admin;
