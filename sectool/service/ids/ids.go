package ids

import (
	"crypto/rand"
	"math/big"
)

const DefaultLength = 6

// base62 character set for LLM-friendly short IDs
const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var maxVal = big.NewInt(int64(len(base62)))

// Generate returns a cryptographically random base62 ID of the specified length.
// If length is 0, uses DefaultLength (6).
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
