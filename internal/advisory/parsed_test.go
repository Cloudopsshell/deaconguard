package advisory

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetParsed(t *testing.T, budget int64) {
	t.Helper()
	previousBudget, previousKept := parsedBudget, parsedKept
	parsedBudget = func() int64 { return budget }
	parsedFeeds.Lock()
	parsedFeeds.largest = 0
	parsedFeeds.Unlock()
	t.Cleanup(func() {
		parsedBudget, parsedKept = previousBudget, previousKept
		parsedFeeds.Lock()
		parsedFeeds.largest = 0
		for key, entry := range parsedFeeds.entries {
			entry.timer.Stop()
			delete(parsedFeeds.entries, key)
		}
		parsedFeeds.Unlock()
	})
}

func cached(kind string) int {
	parsedFeeds.Lock()
	defer parsedFeeds.Unlock()
	count := 0
	for key := range parsedFeeds.entries {
		if len(key) > len(kind) && key[:len(kind)] == kind {
			count++
		}
	}
	return count
}

func TestParsedOnceSharesOneParse(t *testing.T) {
	resetParsed(t, 1<<30)
	var parses atomic.Int32
	release := make(chan struct{})
	parse := func() ([]int, error) {
		parses.Add(1)
		<-release
		return []int{1, 2, 3}, nil
	}
	data := []byte("feed v1")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got, err := parsedOnce("test", data, parse); err != nil || len(got) != 3 {
				t.Errorf("got %v, %v", got, err)
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if parses.Load() != 1 {
		t.Fatalf("%d parses for 8 scans at once", parses.Load())
	}
	// Later scans reuse it; a new download is parsed again.
	parsedOnce("test", data, parse)
	parsedOnce("test", []byte("feed v2"), parse)
	if parses.Load() != 2 {
		t.Fatalf("%d parses", parses.Load())
	}
	// A failed parse isn't kept.
	failing := func() ([]int, error) { parses.Add(1); return nil, errors.New("broken feed") }
	for range 2 {
		if _, err := parsedOnce("test", []byte("broken"), failing); err == nil {
			t.Fatal("no error")
		}
	}
	if parses.Load() != 4 {
		t.Fatalf("a failure was kept: %d parses", parses.Load())
	}
}

// sized returns a parse whose result holds about megabytes of memory.
func sized(megabytes int, parses *atomic.Int32) func() ([]byte, error) {
	return func() ([]byte, error) {
		parses.Add(1)
		data := make([]byte, megabytes<<20)
		for index := range data {
			data[index] = byte(index)
		}
		return data, nil
	}
}

func TestParsedFeedsStayWithinBudget(t *testing.T) {
	resetParsed(t, 100<<20)
	var parses atomic.Int32
	parsedOnce("a", []byte("a"), sized(40, &parses))
	parsedOnce("b", []byte("b"), sized(40, &parses))
	parsedOnce("a", []byte("a"), sized(40, &parses))
	if parses.Load() != 2 || cached("a") != 1 || cached("b") != 1 {
		t.Fatalf("within budget: %d parses", parses.Load())
	}
	// A third makes 120 MB: b, used least recently, goes.
	parsedOnce("c", []byte("c"), sized(40, &parses))
	if cached("a") != 1 || cached("b") != 0 || cached("c") != 1 {
		t.Fatalf("after c: a %d, b %d, c %d", cached("a"), cached("b"), cached("c"))
	}
	// One larger than the budget serves its scan and isn't kept.
	if got, err := parsedOnce("huge", []byte("huge"), sized(150, &parses)); err != nil || len(got) != 150<<20 {
		t.Fatalf("huge: %d bytes, %v", len(got), err)
	}
	if cached("huge") != 0 {
		t.Fatal("a feed over the budget was kept")
	}
}

func TestParsedFeedsMakeRoomBeforeParsing(t *testing.T) {
	resetParsed(t, 100<<20)
	var parses atomic.Int32
	parsedOnce("a", []byte("a"), sized(60, &parses))
	// A second feed as large wouldn't fit beside a: a goes before the parse,
	// so both are never in memory at once.
	parsedOnce("b", []byte("b"), func() ([]byte, error) {
		if cached("a") != 0 {
			t.Error("a was still kept while b was parsed")
		}
		return sized(60, &parses)()
	})
	if cached("a") != 0 || cached("b") != 1 {
		t.Fatalf("after b: a %d, b %d", cached("a"), cached("b"))
	}
	// Small feeds still fit beside it.
	resetParsed(t, 100<<20)
	parsedOnce("c", []byte("c"), sized(20, &parses))
	parsedOnce("d", []byte("d"), sized(20, &parses))
	if cached("c") != 1 || cached("d") != 1 {
		t.Fatalf("small feeds: c %d, d %d", cached("c"), cached("d"))
	}
}

func TestBudgetUnderAMemoryLimit(t *testing.T) {
	for _, test := range []struct{ limit, want int64 }{
		{0, 400 << 20}, {4 << 30, 400 << 20}, {1 << 30, 400 << 20}, {512 << 20, 512 << 20 / 100 * 40},
	} {
		if got := budgetUnder(test.limit); got != test.want {
			t.Errorf("budgetUnder(%d) = %d, want %d", test.limit, got, test.want)
		}
	}
}

func TestParsedFeedsOffAndExpiry(t *testing.T) {
	resetParsed(t, 0)
	var parses atomic.Int32
	parsedOnce("off", []byte("x"), sized(1, &parses))
	parsedOnce("off", []byte("x"), sized(1, &parses))
	if parses.Load() != 2 || cached("off") != 0 {
		t.Fatalf("a budget of 0 still kept feeds: %d parses", parses.Load())
	}
	parsedBudget = func() int64 { return 1 << 30 }
	parsedKept = 500 * time.Millisecond
	parsedOnce("idle", []byte("x"), sized(1, &parses))
	if cached("idle") != 1 {
		t.Fatal("not kept")
	}
	time.Sleep(2 * time.Second)
	if cached("idle") != 0 {
		t.Fatal("kept after its time without a scan")
	}
}
