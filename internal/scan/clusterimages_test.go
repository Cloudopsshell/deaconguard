package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"deaconguard/internal/checks"
)

type fakeImages struct {
	cached map[string]ImageSummary
	read   []string
	off    bool
}

func (f *fakeImages) Cached(image checks.RunningImage, platform string) (ImageSummary, error, bool) {
	if image.Image == "ghcr.io/acme/private:1" {
		return ImageSummary{}, errors.New("unauthorized"), true
	}
	summary, ok := f.cached[image.Image]
	return summary, nil, ok
}

func (f *fakeImages) Check(ctx context.Context, image checks.RunningImage, platform string) (ImageSummary, error) {
	if f.off {
		return ImageSummary{}, ErrRegistryOff
	}
	f.read = append(f.read, image.Image+" "+platform)
	return ImageSummary{}, nil
}

func clusterReport(cluster checks.Cluster) map[string]any {
	return map[string]any{"check_results": map[string]checks.Result{checks.Kubernetes: {
		Status: checks.StatusCompleted, Findings: []checks.Finding{}, Notes: []string{}, Cluster: &cluster}}}
}

func kubernetesResult(t *testing.T, report map[string]any) checks.Result {
	t.Helper()
	return report["check_results"].(map[string]checks.Result)[checks.Kubernetes]
}

func TestClusterImagesBecomeFindings(t *testing.T) {
	digest := "sha256:" + strings.Repeat("d", 64)
	source := &fakeImages{cached: map[string]ImageSummary{
		"nginx:1.25":  {Fixable: 14, Exploited: 2, FixableSeverity: map[string]int{"MEDIUM": 14}, Urgent: []string{"CVE-2023-44487"}},
		"redis:7":     {Fixable: 3, FixableSeverity: map[string]int{"CRITICAL": 1, "LOW": 2}},
		"busybox:1.3": {},
	}}
	report := clusterReport(checks.Cluster{Version: "1.31.2", Architecture: "arm64", Running: []checks.RunningImage{
		{Image: "nginx:1.25", Digest: digest, Namespaces: []string{"shop", "web"}, Pods: 3},
		{Image: "redis:7", Namespaces: []string{"cache"}, Pods: 1},
		{Image: "busybox:1.3"},
		{Image: "ghcr.io/acme/private:1"},
	}})
	if err := EvaluateClusterImages(report, nil, source); err != nil {
		t.Fatal(err)
	}
	result := kubernetesResult(t, report)
	if len(result.Findings) != 2 || len(source.read) != 0 {
		t.Fatalf("findings = %+v, read = %v", result.Findings, source.read)
	}
	redis, nginx := result.Findings[0], result.Findings[1]
	// Known exploited is at least high; the title stays the same as counts change.
	if nginx.Severity != "HIGH" || nginx.Title != "Image nginx:1.25 has vulnerabilities known to be exploited" || nginx.Image != "nginx:1.25" ||
		nginx.Evidence != "nginx:1.25@sha256:dddddddddddd, run by 3 pods in shop, web" || !strings.Contains(nginx.Detail, "2 known to be exploited, 14 fixed by a newer build") ||
		!strings.Contains(nginx.Detail, "Most urgent: CVE-2023-44487") {
		t.Fatalf("nginx = %+v", nginx)
	}
	if redis.Severity != "CRITICAL" || redis.Title != "Image redis:7 has vulnerabilities fixed by a newer build" {
		t.Fatalf("redis = %+v", redis)
	}
	notes := strings.Join(result.Notes, "\n")
	if !strings.Contains(notes, "Checked 3 images") || !strings.Contains(notes, "1 image couldn't be read; private registries need a login on the Images page: ghcr.io/acme/private:1: unauthorized") {
		t.Fatalf("notes = %s", notes)
	}
	if !strings.Contains(result.Summary, "2 findings") {
		t.Fatalf("summary = %s", result.Summary)
	}
}

func TestClusterImagesReadAFewNewOnesPerScan(t *testing.T) {
	source := &fakeImages{cached: map[string]ImageSummary{}}
	var images []string
	for i := 0; i < MaxNewClusterImages+5; i++ {
		images = append(images, "app-"+string(rune('a'+i))+":1")
	}
	// A cluster agent before 1.20.0 sends the references only.
	report := clusterReport(checks.Cluster{Version: "1.31.2", Images: images})
	if err := EvaluateClusterImages(report, nil, source); err != nil {
		t.Fatal(err)
	}
	if len(source.read) != MaxNewClusterImages || source.read[0] != "app-a:1 linux/amd64" {
		t.Fatalf("read = %v", source.read)
	}
	notes := strings.Join(kubernetesResult(t, report).Notes, "\n")
	if !strings.Contains(notes, "5 more images will be checked by the next scans") || !strings.Contains(notes, "older than 1.20.0") {
		t.Fatalf("notes = %s", notes)
	}
}

func TestSummarizeKeepsTheMostUrgent(t *testing.T) {
	result := checks.ContainerResult{OS: "Debian 12", Fixable: 7, Exploited: 1}
	for _, id := range []string{"CVE-1", "CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5", "CVE-6"} {
		result.Findings = append(result.Findings, checks.Finding{Rule: id})
	}
	summary := Summarize(result)
	if strings.Join(summary.Urgent, ",") != "CVE-1,CVE-2,CVE-3,CVE-4,CVE-5" || summary.Fixable != 7 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestClusterImagesSayWhereTheyCameFrom(t *testing.T) {
	source := &fakeImages{off: true, cached: map[string]ImageSummary{
		"nginx:1.25": {Fixable: 1, FixableSeverity: map[string]int{"HIGH": 1}, Node: "node-1"},
		"redis:7":    {},
	}}
	report := clusterReport(checks.Cluster{Version: "1.31.2", Running: []checks.RunningImage{
		{Image: "nginx:1.25", Digest: "sha256:" + strings.Repeat("a", 64)}, {Image: "redis:7"}, {Image: "api:3"}, {Image: "web:4"}}})
	if err := EvaluateClusterImages(report, nil, source); err != nil {
		t.Fatal(err)
	}
	result := kubernetesResult(t, report)
	notes := strings.Join(result.Notes, "\n")
	if len(result.Findings) != 1 || !strings.Contains(notes, "Checked 2 images the pods run for vulnerabilities: 1 from the node agents' Running containers scans, so not downloaded, and 1 read from their registries") ||
		!strings.Contains(notes, "2 images weren't checked: no node agent scanned their containers in the last day, and reading images from registries is turned off") ||
		strings.Contains(notes, "next scans") {
		t.Fatalf("notes = %s", notes)
	}
}

func TestImageDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("9", 64)
	for id, want := range map[string]string{"docker.io/library/nginx@" + digest: digest, digest: "", "nginx@sha256:12": ""} {
		if got := ImageDigest(id); got != want {
			t.Errorf("ImageDigest(%q) = %q", id, got)
		}
	}
}
