package randomsanity

import (
	"appengine"
	"appengine/datastore"
	"log"
	"math/rand" // don't need cryptographically secure randomness here
)

// Keep track of usage stats

// If frequency of database writes becomes a problem, increase SAMPLING_FACTOR
// to only write about every SAMPLING_FACTOR usages.
const SAMPLING_FACTOR = 1

type UsageRecord struct {
	Key string
	N   int64 `datastore:",noindex"`
}

func RecordUsage(ctx appengine.Context, k string, n int64) {
	if rand.Intn(SAMPLING_FACTOR) != 0 {
		return
	}
	key := datastore.NewKey(ctx, "UsageRecord", k, 0, nil)

	err := datastore.RunInTransaction(ctx, func(ctx appengine.Context) error {
		r := UsageRecord{Key: k, N: 0}
		err := datastore.Get(ctx, key, &r)
		if err != nil && err != datastore.ErrNoSuchEntity {
			return err
		}
		r.N += n * SAMPLING_FACTOR
		_, err = datastore.Put(ctx, key, &r)
		return err
	}, nil)
	if err != nil {
		log.Printf("Datastore error: %s", err.Error())
	}
}

func GetUsage(ctx appengine.Context) []UsageRecord {
	var results []UsageRecord

	q := datastore.NewQuery("UsageRecord")
	_, err := q.GetAll(ctx, &results)
	if err != nil {
		log.Printf("Datastore error: %s", err.Error())
	}
	return results
}
