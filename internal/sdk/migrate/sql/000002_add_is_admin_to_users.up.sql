-- Add is_admin column to users table
ALTER TABLE auth.users
ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false;

-- Create an index on is_admin for efficient admin user queries
CREATE INDEX idx_users_is_admin ON auth.users(is_admin) WHERE is_admin = true;

-- Add a comment to document the column
COMMENT ON COLUMN auth.users.is_admin IS 'Indicates whether the user has administrator privileges. Defaults to false for all new users.';
