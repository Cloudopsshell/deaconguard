// Package admission is the cluster agent's Kubernetes validating webhook, in
// warn mode: it checks each workload and role as it is created or changed,
// with the manifest rules, and answers with warnings, which kubectl and
// other clients show. It always allows the object; it never blocks.
package admission

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"deaconguard/internal/iac"
)

// maxWarnings bounds the warnings of one answer; maxWarningLength keeps each
// within what the API server passes on.
const (
	maxWarnings      = 10
	maxWarningLength = 240
	maxRequestBytes  = 3 << 20
)

var severityRank = map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

type review struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Request    *struct {
		UID       string `json:"uid"`
		Namespace string `json:"namespace"`
		Kind      struct {
			Group   string `json:"group"`
			Version string `json:"version"`
			Kind    string `json:"kind"`
		} `json:"kind"`
		Object json.RawMessage `json:"object"`
	} `json:"request"`
}

// Handler answers AdmissionReview requests with warnings for findings at or
// above minimum severity (CRITICAL, HIGH, MEDIUM or LOW).
func Handler(minimum string, logf func(format string, arguments ...any)) http.Handler {
	threshold := severityRank[strings.ToUpper(minimum)]
	if threshold == 0 {
		threshold = severityRank["MEDIUM"]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST an AdmissionReview", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var in review
		if err := json.Unmarshal(body, &in); err != nil || in.Request == nil {
			http.Error(w, "not an AdmissionReview", http.StatusBadRequest)
			return
		}
		warnings := Warnings(in.Request.Object, in.Request.Namespace, threshold)
		if len(warnings) > 0 && logf != nil {
			logf("Admission: %d warnings for a %s in %s", len(warnings), in.Request.Kind.Kind, in.Request.Namespace)
		}
		response := map[string]any{"uid": in.Request.UID, "allowed": true}
		if len(warnings) > 0 {
			response["warnings"] = warnings
		}
		apiVersion := in.APIVersion
		if apiVersion == "" {
			apiVersion = "admission.k8s.io/v1"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"apiVersion": apiVersion, "kind": "AdmissionReview", "response": response})
	})
}

// Warnings checks one object and returns its findings at or above
// threshold as warnings, most severe first.
func Warnings(object json.RawMessage, namespace string, threshold int) []string {
	var node yaml.Node
	if len(object) == 0 || yaml.Unmarshal(object, &node) != nil || len(node.Content) == 0 {
		return nil
	}
	root := node.Content[0]
	var meta struct {
		Metadata struct {
			Namespace       string `json:"namespace"`
			OwnerReferences []any  `json:"ownerReferences"`
		} `json:"metadata"`
		Kind string `json:"kind"`
	}
	json.Unmarshal(object, &meta)
	// A controller's pods, ReplicaSets and Jobs were checked through it.
	if (meta.Kind == "Pod" || meta.Kind == "ReplicaSet" || meta.Kind == "Job") && len(meta.Metadata.OwnerReferences) > 0 {
		return nil
	}
	// Objects being created may not carry their namespace yet.
	if meta.Metadata.Namespace == "" && namespace != "" {
		setNamespace(root, namespace)
	}
	var kept []iac.Finding
	for _, f := range iac.CheckObject("admission", root) {
		if severityRank[strings.ToUpper(f.Severity)] >= threshold {
			kept = append(kept, f)
		}
	}
	for i := 1; i < len(kept); i++ {
		for j := i; j > 0 && severityRank[kept[j].Severity] > severityRank[kept[j-1].Severity]; j-- {
			kept[j], kept[j-1] = kept[j-1], kept[j]
		}
	}
	var warnings []string
	for index, f := range kept {
		if index == maxWarnings {
			warnings = append(warnings, fmt.Sprintf("DeaconGuard: and %d more", len(kept)-maxWarnings))
			break
		}
		warning := fmt.Sprintf("DeaconGuard %s %s: %s", f.Rule, strings.ToLower(f.Severity), f.Title)
		if len(warning) > maxWarningLength {
			warning = warning[:maxWarningLength-1] + "…"
		}
		warnings = append(warnings, warning)
	}
	return warnings
}

func setNamespace(root *yaml.Node, namespace string) {
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value == "metadata" && root.Content[index+1].Kind == yaml.MappingNode {
			metadata := root.Content[index+1]
			metadata.Content = append(metadata.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "namespace"}, &yaml.Node{Kind: yaml.ScalarNode, Value: namespace})
			return
		}
	}
}
