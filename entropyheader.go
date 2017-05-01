package randomsanity

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

func addEntropyHeader(w http.ResponseWriter) {
	// This assumes server has a good crypto/rand
	// implementation. We could memcache an array
	// that is initialized to crypto/rand but updated
	// with every request that comes in with random data.
	var b [32]byte
	n, err := rand.Read(b[:])
	if err == nil && n == len(b) {
		w.Header().Add("X-Entropy", hex.EncodeToString(b[:]))
	}
}
