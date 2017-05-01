package randomsanity

// Best-effort "have we ever seen this array of bytes before?"

import (
	"appengine"
	"appengine/datastore"
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"net/http"
	"time"
)

func looksUnique(ctx appengine.Context, w http.ResponseWriter, b []byte, uID string, tag string) (bool, error) {
	// Test every 16-byte (128-bit) sequence in the input against our database

	// if we get a match, complain!
	match, i, err := unique(ctx, b[:], uID, tag)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, err
	}
	if match != nil {
		notify(ctx, uID, tag, b[i:i+16], "Non Unique")
		if len(match.UserID) > 0 && match.UserID != uID {
			notify(ctx, match.UserID, match.Tag, b[i:i+16], "Non Unique")
		}
		return false, nil
	}
	return true, nil
}

//
// Entities in the 'RB' datastore;
// storing 16 "random we hope" bytes.
//
// First prefixBytes bytes are used as they key,
// the rest are stored as the value, collisions just
// result in multiple values under one key, oldest
// entries first.
//
// The simplest possible storage scheme would be
// 16-byte keys, but that is HUGELY inefficient.
//
// Why 128 bits? We want a false positive rate under
// 1-in-2^60. We're basically running a 'birthday attack'
// so comparing random 128-bit chunks we get
// a chance of collision of any pair of about 1-in-2^64
//

const prefixBytes = 4 // Use 4 for production, 1 for development/testing collisions

type RngUniqueBytesEntry struct {
	Trailing []byte `datastore:",noindex"`
	Time     int64  `datastore:",noindex"`
	UserID   string `datastore:",noindex"`
	Tag      string `datastore:",noindex"`
}
type RngUniqueBytes struct {
	Hits []RngUniqueBytesEntry `datastore:",noindex"`
}

type SecretBytes struct {
	Secret       []byte `datastore:",noindex"`
	CreationTime int64
}

func secretKey(ctx appengine.Context) ([]byte, error) {
	var result []byte

	// Create random secret if it doesn't already exist:
	var secrets []SecretBytes

	q := datastore.NewQuery("SecretBytes")
	if _, err := q.GetAll(ctx, &secrets); err != nil {
		return result, err
	}
	if len(secrets) == 0 {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return result, err
		}
		result = b[:]
		secret := SecretBytes{result, time.Now().Unix()}
		k := datastore.NewIncompleteKey(ctx, "SecretBytes", nil)
		if _, err := datastore.Put(ctx, k, &secret); err != nil {
			return result, err
		}
	} else {
		result = secrets[0].Secret
	}
	return result, nil
}

func i64(b []byte) int64 {
	var result int64
	for i := uint(0); i < uint(len(b)) && i < 8; i++ {
		result = result | (int64(b[i]) << (i * 8))
	}
	return result
}

func dealWithMultiError(err error) error {
	// GetMulti returns either plain errors OR
	// an appengine.MultiError that is an array
	// of errors. We're OK if all the 'errors'
	// are ErrNoSuchEntity; otherwise,
	// we'll report the first error
	switch err.(type) {
	case nil:
		return nil
	case appengine.MultiError:
		m := err.(appengine.MultiError)
		for _, e := range m {
			if e == nil || e == datastore.ErrNoSuchEntity {
				continue
			}
			return e
		}
		return nil
	default:
		return err
	}
	return err
}

func unique(ctx appengine.Context, b []byte, uID string, tag string) (*RngUniqueBytesEntry, int, error) {
	n := len(b) - 15 // Number of queries
	keys := make([]*datastore.Key, n)
	vals := make([]*RngUniqueBytes, n)

	// Input is first be run through AES-128 encryption, to prevent an attacker
	// from intentionally causing database entry collisions.
	secret, err := secretKey(ctx)
	if err != nil {
		return nil, 0, err
	}
	cipher, err := aes.NewCipher(secret)
	if err != nil {
		return nil, 0, err
	}

	chunks := make([][]byte, n)
	for i := 0; i < n; i++ {
		chunks[i] = make([]byte, 16)
		cipher.Encrypt(chunks[i], b[i:i+16])

		keys[i] = datastore.NewKey(ctx, "RB", "", 1+i64(chunks[i][0:prefixBytes]), nil)
		vals[i] = new(RngUniqueBytes)
	}
	err = datastore.GetMulti(ctx, keys, vals)
	err = dealWithMultiError(err)

	if err != nil {
		return nil, 0, err
	}
	for i, hit := range vals {
		for _, h := range hit.Hits {
			if bytes.Equal(h.Trailing, chunks[i][prefixBytes:]) {
				// Rewriting keeps this entry from getting evicted
				// and overwriting the userid/tag prevents the
				// user from getting too many notifications
				write(ctx, chunks[i][:], time.Now().Unix(), "", "")
				return &h, i, nil // ... full match!
			}
		}
	}
	// If no matches, store the first and last 16 bytes. Any future
	// overlapping sequences will trigger a match.
	err = write(ctx, chunks[0][:], time.Now().Unix(), uID, tag)
	if err == nil && n > 1 {
		err = write(ctx, chunks[n-1][:], time.Now().Unix(), uID, tag)
	}
	if err != nil {
		return nil, 0, err
	}
	return nil, 0, nil
}

func write(ctx appengine.Context, b []byte, t int64, uID string, tag string) error {
	const maxEntriesPerKey = 100

	key := datastore.NewKey(ctx, "RB", "", 1+i64(b[0:prefixBytes]), nil)

	err := datastore.RunInTransaction(ctx, func(ctx appengine.Context) error {
		hit := new(RngUniqueBytes)
		err := datastore.Get(ctx, key, hit)
		if err != nil && err != datastore.ErrNoSuchEntity {
			return err
		}
		// Find and remove old entry (if any):
		hits := hit.Hits[:0]
		for _, h := range hit.Hits {
			if !bytes.Equal(h.Trailing, b[prefixBytes:]) {
				hits = append(hits, h)
			}
		}
		// Append new:
		e := RngUniqueBytesEntry{Trailing: b[prefixBytes:], Time: t, UserID: uID, Tag: tag}
		hit.Hits = append(hits, e)
		// Throw out half the old if bucket overflows:
		if len(hit.Hits) > maxEntriesPerKey {
			hit.Hits = hit.Hits[len(hit.Hits)/2:]
		}
		_, err = datastore.Put(ctx, key, hit)
		return err
	}, nil)
	return err
}
