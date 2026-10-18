package agent

import (
	"testing"
	"time"
)

func TestContainerWatch(t *testing.T) {
	running := "aaa\nbbb\n"
	w := &containerWatch{run: func(string) ([]byte, error) { return []byte(running), nil }}
	now := time.Now()
	w.poll(now)
	if got := w.take(); got != 0 {
		t.Errorf("the first look only learns what runs: %d new", got)
	}
	running = "aaa\nbbb\nccc\nddd\n"
	w.poll(now.Add(30 * time.Second))
	if got := w.take(); got != 0 {
		t.Errorf("polled again within a minute: %d new", got)
	}
	w.poll(now.Add(61 * time.Second))
	got := w.take()
	if got != 2 {
		t.Errorf("new = %d, want 2", got)
	}
	w.giveBack(got)
	running = "ccc\n"
	w.poll(now.Add(3 * time.Minute))
	if got := w.take(); got != 2 {
		t.Errorf("a count the server didn't get is kept, and stopped containers aren't new: %d", got)
	}
}
