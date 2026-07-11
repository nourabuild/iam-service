package sqldb

import (
	"crypto/sha256"
	"encoding/hex"
)

// hashTokenBytes returns the SHA-256 digest of a refresh-token bearer string.
// Refresh tokens are high-entropy random values, so a fast cryptographic hash
// is sufficient — what matters is that the database never stores the value
// that an attacker would need to authenticate.
func hashTokenBytes(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

// hashTokenString returns the hex-encoded SHA-256 digest of a token string,
// for columns stored as text (e.g. password reset tokens).
func hashTokenString(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
