package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"deaconguard/internal/admission"
	"deaconguard/internal/agentapi"
	"deaconguard/internal/checks"
	"deaconguard/internal/kube"
	"deaconguard/internal/scan"
)

// connectCluster reaches the API of the cluster the agent runs in; tests
// replace it.
var connectCluster = func() (*kube.Client, error) { return kube.Connect("", "") }

// scanCluster runs a cluster agent's job: the Kubernetes check, read-only,
// with the pod's service account. The server adds the version's support
// and CVEs, so the agent needs to reach only the API and the server.
func scanCluster(ctx context.Context, config Config, job agentapi.Job, emit func(scan.Event)) (map[string]any, error) {
	for _, id := range job.Checks {
		if id != checks.Kubernetes {
			return nil, fmt.Errorf("a cluster agent runs only the Kubernetes check, not %q", id)
		}
	}
	client, err := connectCluster()
	if err != nil {
		return nil, fmt.Errorf("reach the Kubernetes API: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	return scan.RunCluster(ctx, client, config.Cluster, config.HostID, emit)
}

// serveAdmission runs the admission webhook in warn mode when
// $DEACONGUARD_ADMISSION_LISTEN names an address, such as :8443, with the
// certificate and key in $DEACONGUARD_ADMISSION_CERT and _KEY, which the
// Helm chart makes. It stops with ctx.
func serveAdmission(ctx context.Context, log *agentLog) {
	address := os.Getenv("DEACONGUARD_ADMISSION_LISTEN")
	if address == "" {
		return
	}
	pair, err := tls.LoadX509KeyPair(os.Getenv("DEACONGUARD_ADMISSION_CERT"), os.Getenv("DEACONGUARD_ADMISSION_KEY"))
	if err != nil {
		log.warn("The admission webhook can't start: %v", err)
		return
	}
	mux := http.NewServeMux()
	mux.Handle("POST /validate", admission.Handler(os.Getenv("DEACONGUARD_ADMISSION_SEVERITY"), func(format string, arguments ...any) {
		log.info(format, arguments...)
	}))
	server := &http.Server{
		Addr: address, Handler: mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	log.info("Admission webhook (warn mode) on %s", address)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.warn("The admission webhook stopped: %v", err)
	}
}
