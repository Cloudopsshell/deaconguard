//go:build linux

package live

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestConnectCost times many connections with live detection off and on,
// as a busy server makes them. Opt-in, like TestKernel:
// DEACONGUARD_LIVE_COST=1.
func TestConnectCost(t *testing.T) {
	if os.Getenv("DEACONGUARD_LIVE_COST") != "1" {
		t.Skip("set DEACONGUARD_LIVE_COST=1 to time connections with the watchers loaded")
	}
	const count = 200_000
	connect := func() time.Duration {
		start := time.Now()
		address := &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}}
		for range count {
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			unix.Connect(fd, address)
			unix.Close(fd)
		}
		return time.Since(start)
	}
	off := connect()
	detector := NewDetector("", t.Logf)
	detector.SetEnabled(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go detector.Run(ctx)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if status, _ := detector.Take(); status.State == StateActive {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("detection didn't start: %+v", status)
		}
	}
	detector.Take()
	on := connect()
	time.Sleep(6 * time.Second)
	status, alerts := detector.Take()
	t.Logf("%d connections: %v off, %v on (%.1f%% slower); agent %.2f%% CPU, %d MB; %d events in the last hour, %d alerts",
		count, off.Round(time.Millisecond), on.Round(time.Millisecond), (float64(on)/float64(off)-1)*100,
		status.CPUPercent, status.MemoryBytes>>20, status.EventsLastHour, len(alerts))
}
