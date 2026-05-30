package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
)

const DefaultLength = 6

// EntityLength is a shorter length for low-volume entity IDs (sessions, rules, notes).
const EntityLength = 4

// base62 character set for LLM-friendly short IDs
const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var maxVal = big.NewInt(int64(len(base62)))

// Generate returns a cryptographically random base62 ID of the specified length.
func Generate(length int) string {
	if length <= 0 {
		length = DefaultLength
	}

	result := make([]byte, length)
	for i := range length {
		n, err := rand.Int(rand.Reader, maxVal)
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		result[i] = base62[n.Int64()]
	}

	return string(result)
}

// Derive returns a deterministic base62 ID of the given length from the joined parts.
func Derive(length int, parts ...string) string {
	if length <= 0 {
		length = DefaultLength
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	n := new(big.Int).SetBytes(sum[:])
	result := make([]byte, length)
	rem := new(big.Int)
	for i := range length {
		n.QuoRem(n, maxVal, rem)
		result[i] = base62[rem.Int64()]
	}
	return string(result)
}

// IsValid returns true if the ID contains only valid base62 characters.
// Used to validate user-supplied IDs to prevent path traversal.
func IsValid(id string) bool {
	if id == "" {
		return false
	}
	for _, c := range id {
		isDigit := c >= '0' && c <= '9'
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		if !isDigit && !isUpper && !isLower {
			return false
		}
	}
	return true
}
