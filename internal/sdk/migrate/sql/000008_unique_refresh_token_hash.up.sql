-- Backstop for refresh-token rotation: the stored token hash must be unique.
--
-- Tokens now carry a random jti so collisions cannot occur at issuance, but a
-- unique index guarantees the invariant at the storage layer too — a duplicate
-- hash would make GetRefreshTokenByToken's result row ambiguous, which is what
-- allowed revoked-token replay to slip through.

-- Remove any existing duplicate-hash rows (artifacts of pre-jti same-second
-- token issuance), keeping the newest row of each group.
DELETE FROM auth.refresh_tokens a
USING auth.refresh_tokens b
WHERE a.token = b.token
  AND a.id < b.id;

DROP INDEX IF EXISTS auth.idx_refresh_tokens_token;
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_unique ON auth.refresh_tokens (token);
