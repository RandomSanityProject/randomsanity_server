package randomsanity

import (
	"appengine"
	"appengine/memcache"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Limit something (identified by key) to at most max per timespan
// State stored in the memcache, so this is "best-effort"
// Returns true if rate limit is hit.
func RateLimit(ctx appengine.Context, key string, max uint64, timespan time.Duration) (bool, error) {
	value, err := memcache.Increment(ctx, key, -1, max+1)
	if err != nil {
		return false, err
	}
	// value 0 : ran into request limit
	if value == 0 {
		return true, nil
	}
	// value max means it wasn't set before, so
	// rewrite to set correct expiration time:
	if value == max {
		item, err := memcache.Get(ctx, key)
		if err != nil {
			return false, err
		}
		item.Expiration = timespan
		// There is a race condition here, but it is mostly harmless
		// (extra requests above the rate limit could slip through)
		memcache.Set(ctx, item)
	}
	return false, nil
}

// Rate limit, and write stuff to w:
func RateLimitResponse(ctx appengine.Context, w http.ResponseWriter, key string, max uint64, timespan time.Duration) (bool, error) {
	limit, err := RateLimit(ctx, key, max, timespan)
	if err != nil {
		http.Error(w, "RateLimit error", http.StatusInternalServerError)
		return false, err
	}
	if limit {
		w.Header().Add("Content-Type", "text/plain")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "Request limit exceeded")
		return true, nil
	}
	return false, nil
}

// Get a reasonable memcache key from IPv4 or IPv6 address
func IPKey(prefix string, ipaddr string) string {
	// If it is a super-long IPv6: use first four parts
	ipv6parts := strings.Split(ipaddr, ":")
	if len(ipv6parts) > 4 {
		return prefix + strings.Join(ipv6parts[0:4], ":")
	}
	return prefix + ipaddr
}
