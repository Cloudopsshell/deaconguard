package agent

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"deaconguard/internal/agentapi"
	"deaconguard/internal/live"
)

// runLive runs live detection and reports it to the server: its status
// every agentapi.LiveInterval, and alerts within a second or so. The
// server's reply turns it on or off and asks for test alerts.
func runLive(ctx context.Context, current *atomic.Pointer[serverClient], log *agentLog) {
	detector := live.NewDetector(os.Getenv("DEACONGUARD_HOST_ROOT"), func(format string, arguments ...any) {
		log.info(format, arguments...)
	})
	go detector.Run(ctx)
	ticker := time.NewTicker(agentapi.LiveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-detector.Ready():
			// Alerts often come in a burst: send them together.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		c := current.Load()
		if c == nil {
			continue
		}
		status, alerts := detector.Take()
		for len(alerts) > 0 || status.State != "" {
			batch := alerts[:min(len(alerts), agentapi.MaxLiveAlerts)]
			var reply agentapi.LiveReply
			err := c.call(ctx, http.MethodPost, agentapi.PathLive, agentapi.LiveReport{Status: status, Alerts: batch}, &reply, 30*time.Second)
			if err != nil {
				detector.Return(alerts)
				// A server older than 1.27.0 has nowhere to send alerts to:
				// stop until it's upgraded.
				if errors.Is(err, errRejected) && strings.Contains(err.Error(), "HTTP 404") {
					detector.SetEnabled(false)
				}
				break
			}
			detector.SetEnabled(reply.Enabled)
			if reply.Test {
				detector.AskTest()
			}
			alerts = alerts[len(batch):]
			status.State = ""
		}
	}
}

// serverClient names client where Run's local variable of that name hides it.
type serverClient = client
