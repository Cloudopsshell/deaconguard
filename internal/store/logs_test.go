package store

import (
	"strings"
	"testing"
	"time"
)

func TestLogsAreCleanedFilteredAndPaged(t *testing.T) {
	withTempDataDir(t)
	host := addTestHost(t, "web-01.example", TransportAgent)
	Log(LogServer, "", LogInfo, "DeaconGuard server started")
	if err := AddLogs(LogAgent, host.ID, []LogLine{
		{At: time.Now().Add(-time.Minute), Level: LogInfo, Message: "Connected to the server"},
		{At: time.Now().Add(48 * time.Hour), Level: "panic", Message: "a future time and an unknown level"},
		{Level: LogWarning, Message: "Cannot reach the server: 100% down_now"},
		{Level: LogError, Message: strings.Repeat("x", 5000)},
	}); err != nil {
		t.Fatal(err)
	}

	all, more, err := Logs(LogQuery{})
	if err != nil || more || len(all) != 5 || all[0].Level != LogError || all[4].Message != "DeaconGuard server started" {
		t.Fatalf("Logs() = %+v, %v, %v", all, more, err)
	}
	if long := all[0].Message; len(long) > maxLogMessage+len("…") || !strings.HasSuffix(long, "…") {
		t.Fatalf("long message kept %d bytes", len(long))
	}
	cleaned := all[2]
	if cleaned.Level != LogInfo || cleaned.Host != "web-01.example" {
		t.Fatalf("cleaned = %+v", cleaned)
	}
	if at, _ := time.Parse(time.RFC3339Nano, cleaned.At); at.After(time.Now().Add(time.Minute)) {
		t.Fatalf("a future time was kept: %s", cleaned.At)
	}

	if warnings, _, _ := Logs(LogQuery{Level: LogWarning}); len(warnings) != 2 {
		t.Fatalf("warnings and errors = %d", len(warnings))
	}
	if agent, _, _ := Logs(LogQuery{Source: LogAgent, HostID: host.ID}); len(agent) != 4 {
		t.Fatalf("agent entries = %d", len(agent))
	}
	// % and _ are matched literally, not as wildcards.
	if found, _, _ := Logs(LogQuery{Search: "100% down_now"}); len(found) != 1 {
		t.Fatalf("search = %d", len(found))
	}
	if found, _, _ := Logs(LogQuery{Search: "1%0"}); len(found) != 0 {
		t.Fatalf("a %% in the search matched as a wildcard: %d", len(found))
	}
	if byHost, _, _ := Logs(LogQuery{Search: "web-01"}); len(byHost) != 4 {
		t.Fatalf("search by host name = %d", len(byHost))
	}

	first, more, _ := Logs(LogQuery{Limit: 2})
	second, _, _ := Logs(LogQuery{Limit: 2, Before: first[1].ID})
	if !more || len(first) != 2 || len(second) != 2 || second[0].ID >= first[1].ID {
		t.Fatalf("pages = %+v / %+v", first, second)
	}
}
