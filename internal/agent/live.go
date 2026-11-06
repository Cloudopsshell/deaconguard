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
	"deaconguard/internal/containers"
	"deaconguard/internal/live"
	"deaconguard/internal/local"
)

// runLive runs live detection and reports it to the server: its status
// every agentapi.LiveInterval, and alerts within a second or so. The
// server's reply turns it on or off and asks for test alerts.
func runLive(ctx context.Context, current *atomic.Pointer[serverClient], log *agentLog) {
	detector := live.NewDetector(os.Getenv("DEACONGUARD_HOST_ROOT"), func(format string, arguments ...any) {
		log.info(format, arguments...)
	})
	detector.SetContainerLookup(lookupContainer)
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
				detector.Unsent(status)
				// A server older than 1.27.0 has nowhere to send alerts to:
				// stop until it's upgraded.
				if errors.Is(err, errRejected) && strings.Contains(err.Error(), "HTTP 404") {
					detector.SetEnabled(false)
				}
				break
			}
			detector.SetEnabled(reply.Enabled)
			detector.SetAllowlist(reply.Allow)
			if reply.Test {
				detector.AskTest()
			}
			alerts = alerts[len(batch):]
			status.State, status.Allowed = "", nil
		}
	}
}

// lookupContainer asks the machine's container runtime, chrooted into the
// host's root in a container, for a container's name and image.
func lookupContainer(id string) (live.Container, bool, error) {
	machine, err := local.New()
	if err != nil {
		return live.Container{}, false, err
	}
	output, err := machine.Run(containers.LookupCommand(id), nil, 4096, 20*time.Second)
	if err != nil {
		return live.Container{}, false, err
	}
	found, ok := containers.ParseLookup(output)
	if !ok {
		return live.Container{}, false, nil
	}
	return live.Container{Name: found.Name, Image: found.Image, Namespace: found.Namespace, Pod: found.Pod}, true, nil
}

// serverClient names client where Run's local variable of that name hides it.
type serverClient = client
