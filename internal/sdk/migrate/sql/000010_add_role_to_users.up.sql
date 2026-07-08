ALTER TABLE auth.users
ADD COLUMN role TEXT NOT NULL DEFAULT 'user';

UPDATE auth.users
SET role = 'admin'
WHERE is_admin = true;

ALTER TABLE auth.users
ADD CONSTRAINT users_role_check CHECK (role IN ('user', 'admin'));

CREATE INDEX idx_users_role ON auth.users(role);

COMMENT ON COLUMN auth.users.role IS 'Role name used for authorization. Mirrors is_admin during the compatibility period.';
