package advisory

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"deaconguard/internal/memlimit"
)

// Parsing a large feed, such as Canonical's OVAL for a release (hundreds of
// megabytes of XML), costs several seconds of CPU, half a minute on a small
// server. A feed changes at most every 12 hours, so scans share the parsed
// feed: each is parsed once, kept while scans use it, and dropped after
// parsedKept without one, or sooner when the parsed feeds would take more
// memory than the budget.

// parsedKept is how long a parsed feed stays after its last use.
var parsedKept = 30 * time.Minute

// defaultParsedBudget is the memory parsed feeds may take, in bytes: one
// Ubuntu release's OVAL (about 275 MB) with Debian's and Red Hat's. Set
// DEACONGUARD_FEED_CACHE_MB to change it, or to 0 to parse for every scan.
// Under a memory limit, such as a container's, the default is at most
// limitShare percent of it: parsing a feed takes about as much again.
const (
	defaultParsedBudget = 400 << 20
	limitShare          = 40
)

// parsedBudget reads the budget once; tests change it.
var parsedBudget = sync.OnceValue(func() int64 {
	if text := os.Getenv("DEACONGUARD_FEED_CACHE_MB"); text != "" {
		if megabytes, err := strconv.ParseInt(text, 10, 64); err == nil && megabytes >= 0 {
			return megabytes << 20
		}
	}
	return budgetUnder(memlimit.Limit())
})

func budgetUnder(limit int64) int64 {
	if limit > 0 {
		return min(defaultParsedBudget, limit/100*limitShare)
	}
	return defaultParsedBudget
}

type parsedEntry struct {
	ready    chan struct{}
	value    any
	err      error
	size     int64
	lastUsed time.Time
	timer    *time.Timer
}

var parsedFeeds = struct {
	sync.Mutex
	entries map[string]*parsedEntry
	// parsing serializes parses, so that each one's memory can be measured.
	parsing sync.Mutex
	// largest is the most memory a parsed feed has taken: what the next
	// parse is expected to need room for.
	largest int64
}{entries: map[string]*parsedEntry{}}

// parsedOnce returns kind's feed data parsed by parse, parsing it only when
// these exact bytes haven't been parsed recently. Scans that ask at the same
// time wait for one parse. The parsed value must not be changed by its users.
func parsedOnce[T any](kind string, data []byte, parse func() (T, error)) (T, error) {
	budget := parsedBudget()
	if budget == 0 {
		return parse()
	}
	sum := sha256.Sum256(data)
	key := kind + " " + hex.EncodeToString(sum[:])
	parsedFeeds.Lock()
	entry, found := parsedFeeds.entries[key]
	if !found {
		// A feed replaced by a newer download is no longer asked for, so it
		// goes when its time runs out.
		entry = &parsedEntry{ready: make(chan struct{})}
		parsedFeeds.entries[key] = entry
		entry.timer = time.AfterFunc(parsedKept, func() { forgetParsed(key, entry) })
	} else {
		entry.timer.Reset(parsedKept)
	}
	entry.lastUsed = time.Now()
	parsedFeeds.Unlock()
	if !found {
		value, size, err := measuredParse(key, budget, parse)
		entry.value, entry.err = value, err
		parsedFeeds.Lock()
		entry.size = size
		// The time without a scan counts from when the parse is done.
		entry.timer.Reset(parsedKept)
		parsedFeeds.Unlock()
		close(entry.ready)
		if err != nil {
			forgetParsed(key, entry)
		} else {
			keepWithinBudget(key, budget)
		}
	}
	<-entry.ready
	if entry.err != nil {
		var zero T
		return zero, entry.err
	}
	return entry.value.(T), nil
}

// measuredParse parses, and says how much memory the result holds: the
// growth over the parse of the heap memory in use, between two collections,
// which counts the pages its many small objects take, not only the objects.
// Room is made first, so the feeds kept and the one being parsed fit in the
// budget together, rather than only once the parse is done.
func measuredParse[T any](key string, budget int64, parse func() (T, error)) (T, int64, error) {
	parsedFeeds.parsing.Lock()
	defer parsedFeeds.parsing.Unlock()
	makeRoom(key, budget)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	value, err := parse()
	runtime.GC()
	runtime.ReadMemStats(&after)
	size := max(0, int64(after.HeapInuse)-int64(before.HeapInuse))
	if err == nil {
		parsedFeeds.Lock()
		parsedFeeds.largest = max(parsedFeeds.largest, size)
		parsedFeeds.Unlock()
	}
	return value, size, err
}

// makeRoom drops the least recently used parsed feeds while they and a
// feed as large as the largest one parsed so far would take more than
// budget. Scans using a dropped feed keep their copy until they are done.
func makeRoom(parsing string, budget int64) {
	parsedFeeds.Lock()
	defer parsedFeeds.Unlock()
	for {
		total := parsedFeeds.largest
		var oldest string
		var oldestEntry *parsedEntry
		for key, entry := range parsedFeeds.entries {
			total += entry.size
			if key == parsing || entry.size == 0 {
				continue
			}
			if oldestEntry == nil || entry.lastUsed.Before(oldestEntry.lastUsed) {
				oldest, oldestEntry = key, entry
			}
		}
		if total <= budget || oldestEntry == nil {
			return
		}
		oldestEntry.timer.Stop()
		delete(parsedFeeds.entries, oldest)
	}
}

// keepWithinBudget drops the least recently used parsed feeds while all of
// them take more than budget, the one just parsed last of all: a feed larger
// than the budget by itself serves the scans waiting for it, and isn't kept.
func keepWithinBudget(newest string, budget int64) {
	parsedFeeds.Lock()
	defer parsedFeeds.Unlock()
	for {
		total := int64(0)
		var oldest string
		var oldestEntry *parsedEntry
		for key, entry := range parsedFeeds.entries {
			total += entry.size
			if key == newest {
				continue
			}
			if oldestEntry == nil || entry.lastUsed.Before(oldestEntry.lastUsed) {
				oldest, oldestEntry = key, entry
			}
		}
		if total <= budget {
			return
		}
		if oldestEntry == nil {
			oldest, oldestEntry = newest, parsedFeeds.entries[newest]
			if oldestEntry == nil {
				return
			}
		}
		oldestEntry.timer.Stop()
		delete(parsedFeeds.entries, oldest)
	}
}

func forgetParsed(key string, entry *parsedEntry) {
	parsedFeeds.Lock()
	defer parsedFeeds.Unlock()
	if parsedFeeds.entries[key] == entry {
		entry.timer.Stop()
		delete(parsedFeeds.entries, key)
	}
}
