DROP INDEX IF EXISTS auth.idx_refresh_tokens_token_unique;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON auth.refresh_tokens (token);
