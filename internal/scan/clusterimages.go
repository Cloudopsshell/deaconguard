package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"deaconguard/internal/checks"
)

// The server checks the images a cluster's pods run, as image scans do:
// each build is read from its registry once and its result kept for a day
// (ClusterImages), so scanning a cluster again, or every minute when it
// changes, reads only images it hasn't seen. A scan reads at most
// MaxNewClusterImages new ones, within ClusterImagesBudget; the next scan
// reads the rest.
const (
	MaxClusterImages    = 100
	MaxNewClusterImages = 10
	ClusterImagesBudget = 10 * time.Minute
)

// ImageSummary is what a cluster scan keeps of an image's check: the
// counts, and the most urgent vulnerabilities by name.
type ImageSummary struct {
	OS              string
	Fixable         int
	Exploited       int
	FixableSeverity map[string]int
	// Urgent are the IDs of the most urgent vulnerabilities to fix, at most 5.
	Urgent []string
	// Node names the machine whose agent read the build from a running
	// container, so nothing was downloaded; empty when it was read from
	// its registry.
	Node string
}

// ErrRegistryOff is Check's answer when reading images from registries is
// turned off: only builds node agents read are checked.
var ErrRegistryOff = errors.New("reading images from registries is turned off")

// ImageDigest is the digest in a container's image ID, such as
// docker.io/library/nginx@sha256:…, as crictl and the pods' status report
// it; "" for an ID without a repository, which no pod's status matches.
func ImageDigest(imageID string) string {
	_, digest, found := strings.Cut(imageID, "@")
	if !found || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return ""
	}
	return digest
}

// NodeImage is a build a node agent read from a running container.
type NodeImage struct {
	Digest  string
	Summary ImageSummary
}

// NodeImages are the builds of the running containers in a report's
// Running containers check, once the server has checked them.
func NodeImages(report map[string]any) []NodeImage {
	raw, ok := report["check_results"]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var results map[string]checks.Result
	if json.Unmarshal(encoded, &results) != nil {
		return nil
	}
	result, ok := results[checks.Containers]
	if !ok || result.Status == checks.StatusFailed || result.Status == checks.StatusSkipped {
		return nil
	}
	var list []NodeImage
	seen := map[string]bool{}
	for _, container := range result.Containers {
		digest := ImageDigest(container.ImageID)
		// Only containers the server checked: running ones, with a result.
		if digest == "" || seen[digest] || !container.Scanned() || container.Severity == nil {
			continue
		}
		seen[digest] = true
		list = append(list, NodeImage{Digest: digest, Summary: Summarize(container)})
	}
	return list
}

// Summarize keeps what a cluster scan needs of an image's check.
func Summarize(result checks.ContainerResult) ImageSummary {
	summary := ImageSummary{OS: result.OS, Fixable: result.Fixable, Exploited: result.Exploited, FixableSeverity: result.FixableSeverity}
	seen := map[string]bool{}
	for _, finding := range result.Findings {
		if len(summary.Urgent) == 5 {
			break
		}
		if !seen[finding.Rule] {
			seen[finding.Rule] = true
			summary.Urgent = append(summary.Urgent, finding.Rule)
		}
	}
	return summary
}

// ClusterImages checks images for cluster scans; the server's keeps the
// results. Cached returns a kept result, or a kept failure, without reading
// anything; Check reads the image from its registry and keeps the result.
type ClusterImages interface {
	Cached(image checks.RunningImage, platform string) (summary ImageSummary, failure error, found bool)
	Check(ctx context.Context, image checks.RunningImage, platform string) (ImageSummary, error)
}

// EvaluateClusterImages adds a finding for each image the cluster's pods
// run that has vulnerabilities to fix, in place in the report's check
// results.
func EvaluateClusterImages(report map[string]any, emit func(Event), source ClusterImages) error {
	raw, ok := report["check_results"]
	if !ok || raw == nil || source == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	var results map[string]checks.Result
	if err := json.Unmarshal(encoded, &results); err != nil {
		return fmt.Errorf("read check results: %w", err)
	}
	result, ok := results[checks.Kubernetes]
	if !ok || result.Cluster == nil || result.Status == checks.StatusFailed {
		return nil
	}
	list := result.Cluster.Running
	tagsOnly := len(list) == 0
	if tagsOnly {
		// Cluster agents before 1.20.0 send the images' references only.
		for _, image := range result.Cluster.Images {
			list = append(list, checks.RunningImage{Image: image})
		}
	}
	if len(list) == 0 {
		return nil
	}
	progress := &reporter{emit: emit}
	progress.startPhase(checks.Kubernetes, fmt.Sprintf("Checking the %s the pods run", plural(len(list), "image", "images")))
	platform := "linux/amd64"
	if result.Cluster.Architecture != "" {
		platform = "linux/" + result.Cluster.Architecture
	}
	if len(list) > MaxClusterImages {
		result.Notes = append(result.Notes, fmt.Sprintf("Only the first %d of the %d images the pods run were checked.", MaxClusterImages, len(list)))
		list = list[:MaxClusterImages]
	}
	ctx, cancel := context.WithTimeout(context.Background(), ClusterImagesBudget)
	defer cancel()
	checked, read, later, fromNodes, off := 0, 0, 0, 0, 0
	var failures []string
	for _, image := range list {
		summary, failure, found := source.Cached(image, platform)
		if !found {
			if read >= MaxNewClusterImages || ctx.Err() != nil {
				later++
				continue
			}
			read++
			progress.info("Reading %s from its registry", image.Image)
			summary, failure = source.Check(ctx, image, platform)
			if errors.Is(failure, ErrRegistryOff) {
				read--
				off++
				continue
			}
		}
		if failure != nil {
			message := failure.Error()
			if !strings.Contains(message, image.Image) {
				message = image.Image + ": " + message
			}
			failures = append(failures, message)
			continue
		}
		checked++
		if summary.Node != "" {
			fromNodes++
		}
		if finding, ok := imageFinding(image, summary); ok {
			result.Findings = append(result.Findings, finding)
		}
	}
	if checked > 0 {
		note := fmt.Sprintf("Checked %s the pods run for vulnerabilities", plural(checked, "image", "images"))
		switch fromNodes {
		case checked:
			note += ", all from the node agents' Running containers scans, so nothing was downloaded."
		case 0:
			note += ", each read from its registry once a day, as image scans do."
		default:
			note += fmt.Sprintf(": %d from the node agents' Running containers scans, so not downloaded, and %d read from their registries once a day.", fromNodes, checked-fromNodes)
		}
		result.Notes = append(result.Notes, note)
	}
	if off > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("%s weren't checked: no node agent scanned their containers in the last day, and reading images from registries is turned off on the server.",
			plural(off, "image", "images")))
	}
	if tagsOnly && checked > 0 {
		result.Notes = append(result.Notes, "The cluster agent is older than 1.20.0, so each image's tag was checked as it is now, which may be a newer build than the pods run. Upgrade the cluster agent to check the builds they run.")
	}
	if later > 0 {
		result.Notes = append(result.Notes, fmt.Sprintf("%s will be checked by the next scans: a scan reads at most %d new images from their registries, to keep it light.",
			plural(later, "more image", "more images"), MaxNewClusterImages))
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		note := fmt.Sprintf("%s couldn't be read; private registries need a login on the Images page: %s", plural(len(failures), "image", "images"), failures[0])
		if len(failures) > 1 {
			note += fmt.Sprintf(" (and %d more)", len(failures)-1)
		}
		result.Notes = append(result.Notes, note)
	}
	summarizeCluster(&result)
	progress.findings(result)
	progress.endPhase(result.Status, result.Summary)
	results[checks.Kubernetes] = result
	report["check_results"] = results
	return nil
}

// imageFinding reports an image with vulnerabilities to fix. Its title
// stays the same while the counts change, so a rebuild with the same kind
// of problems isn't notified as new.
func imageFinding(image checks.RunningImage, summary ImageSummary) (checks.Finding, bool) {
	if summary.Fixable == 0 && summary.Exploited == 0 {
		return checks.Finding{}, false
	}
	severity := "LOW"
	for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if summary.FixableSeverity[level] > 0 {
			severity = level
			break
		}
	}
	title := "Image " + image.Image + " has vulnerabilities fixed by a newer build"
	if summary.Exploited > 0 {
		title = "Image " + image.Image + " has vulnerabilities known to be exploited"
		if severityRank(severity) < severityRank("HIGH") {
			severity = "HIGH"
		}
	}
	var counts []string
	if summary.Exploited > 0 {
		counts = append(counts, fmt.Sprintf("%d known to be exploited", summary.Exploited))
	}
	counts = append(counts, fmt.Sprintf("%d fixed by a newer build", summary.Fixable))
	detail := "The build the pods run has " + strings.Join(counts, ", ") + "."
	if len(summary.Urgent) > 0 {
		detail += " Most urgent: " + strings.Join(summary.Urgent, ", ") + "."
	}
	detail += " Rebuild the image on an updated base, or update to a newer release, and roll the workloads that use it; scan it on the Images page to see each vulnerability."
	evidence := image.Image
	if image.Digest != "" && len(image.Digest) > 19 {
		// Short, as docker shows image IDs: the build, recognizably.
		evidence += "@" + image.Digest[:19]
	}
	if len(image.Namespaces) > 0 {
		evidence += fmt.Sprintf(", run by %s in %s", plural(image.Pods, "pod", "pods"), strings.Join(image.Namespaces, ", "))
	}
	return checks.Finding{Rule: "DG-K8S-050", Severity: severity, Title: title, Detail: detail, Evidence: evidence, Image: image.Image,
		Exploited: summary.Exploited > 0, Fixable: summary.Fixable > 0}, true
}

func plural(count int, one, many string) string {
	if count == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", count, many)
}
