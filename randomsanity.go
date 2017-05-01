// AppEngine-based server to sanity check byte arrays
// that are supposed to be random.
package randomsanity

import (
	"appengine"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func init() {
	// Main API point, sanity check hex bytes
	http.HandleFunc("/v1/q/", submitBytesHandler)

	// Start an email loop to get an id token, to be
	// notified via email of failures:
	http.HandleFunc("/v1/registeremail/", registerEmailHandler)

	// Remove an id token
	http.HandleFunc("/v1/unregister/", unRegisterIDHandler)

	// Development/testing...
	http.HandleFunc("/v1/debug", debugHandler)

	// Redirect to www. home page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "http://www.randomsanity.org/", 301)
	})
}

func debugHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")

	// Code useful for development/testing:

	//	fmt.Fprint(w, "***r.Header headers***\n")
	//	r.Header.Write(w)

	//	ctx := appengine.NewContext(r)
	//	fmt.Fprint(w, "Usage data:\n")
	//	for _, u := range GetUsage(ctx) {
	//		fmt.Fprintf(w, "%s,%d\n", u.Key, u.N)
	//	}
}

func submitBytesHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) != 4 {
		http.Error(w, "Invalid GET", http.StatusBadRequest)
		return
	}
	b, err := hex.DecodeString(parts[len(parts)-1])
	if err != nil {
		http.Error(w, "Invalid hex", http.StatusBadRequest)
		return
	}
	// Need at least 16 bytes to hit the 1-in-2^60 false positive rate
	if len(b) < 16 {
		http.Error(w, "Must provide 16 or more bytes", http.StatusBadRequest)
		return
	}

	ctx := appengine.NewContext(r)

	// Users that register can append id=....&tag=.... so
	// they're notified if somebody else submits
	// the same random bytes
	uID := r.FormValue("id")
	dbKey, _ := userID(ctx, uID)
	tag := ""
	if dbKey == nil {
		uID = ""
	} else {
		tag = r.FormValue("tag")
		if len(tag) > 64 {
			tag = "" // Tags must be short
		}
	}

	// Rate-limit by IP address, with a much higher limit for registered users
	// If more complicated logic is needed because of abuse a per-user limit
	// could be stored in the datastore, but running into the 600-per-hour-per-ip
	// limit should be rare (maybe a sysadmin has 200 virtual machines
	// behind the same IP address and restarts them more than three times in a hour....)
	var ratelimit uint64 = 60
	if len(uID) > 0 {
		ratelimit = 600
	}
	limited, err := RateLimitResponse(ctx, w, IPKey("q", r.RemoteAddr), ratelimit, time.Hour)
	if err != nil || limited {
		return
	}

	w.Header().Add("Content-Type", "application/json")

	// Returns some randomness caller can use to mix in to
	// their PRNG:
	addEntropyHeader(w)

	// First, some simple tests for non-random input:
	result, reason := LooksRandom(b)
	if !result {
		RecordUsage(ctx, "Fail_"+reason, 1)
		fmt.Fprint(w, "false")
		notify(ctx, uID, tag, b, reason)
		return
	}

	// Try to catch two machines with insufficient starting
	// entropy generating identical streams of random bytes.
	if len(b) > 64 {
		b = b[0:64] // Prevent DoS from excessive datastore lookups
	}
	unique, err := looksUnique(ctx, w, b, uID, tag)
	if err != nil {
		return
	}
	if unique {
		RecordUsage(ctx, "Success", 1)
		fmt.Fprint(w, "true")
	} else {
		RecordUsage(ctx, "Fail_Nonunique", 1)
		fmt.Fprint(w, "false")
	}
}
