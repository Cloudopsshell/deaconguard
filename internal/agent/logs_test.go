package agent

import (
	"fmt"
	"testing"
)

func TestAgentLogKeepsTheNewestLinesAndCountsTheRest(t *testing.T) {
	var journal []string
	log := &agentLog{journal: func(format string, arguments ...any) { journal = append(journal, fmt.Sprintf(format, arguments...)) }}
	for i := range maxPendingLogLines + 3 {
		log.info("line %d", i)
	}
	log.warn("Cannot reach the server")
	if len(journal) != maxPendingLogLines+4 {
		t.Fatalf("journal has %d lines", len(journal))
	}
	if len(log.pending) != maxPendingLogLines || log.dropped != 4 {
		t.Fatalf("pending = %d, dropped = %d", len(log.pending), log.dropped)
	}
	if first, last := log.pending[0], log.pending[len(log.pending)-1]; first.Message != "line 4" || last.Level != "warning" {
		t.Fatalf("first = %+v, last = %+v", first, last)
	}
}
