package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"deaconguard/internal/store"
)

func TestSBOMDownload(t *testing.T) {
	s := newTestServer(t, nil)
	host := decode[store.Host](t, request(t, s, http.MethodPost, "/api/hosts", map[string]any{"transport": "local"}))
	scan, err := store.CreateScan(host, []string{store.CheckPackages, "libraries"})
	if err != nil {
		t.Fatal(err)
	}
	report := map[string]any{
		"host_id": host.ID, "address": "web-01", "os": "Ubuntu 24.04 LTS", "scanned_at": "2026-10-18T10:00:00Z",
		"findings": []any{}, "package_manager": "dpkg", "distro": map[string]any{"id": "ubuntu", "version_id": "24.04"},
		"installed_packages": []any{map[string]any{"name": "openssl", "version": "3.0.13-0ubuntu3.4", "arch": "amd64"}},
		"check_results": map[string]any{"libraries": map[string]any{
			"status": "completed", "summary": "No known vulnerabilities in 1 libraries", "findings": []any{}, "notes": []any{},
			"libraries": map[string]any{"files": 1, "libraries": []any{
				map[string]any{"ecosystem": "npm", "name": "lodash", "version": "4.17.21", "paths": []any{"/srv/app/package-lock.json"}},
			}},
		}},
	}
	if err := store.CompleteScan(scan.ID, report); err != nil {
		t.Fatal(err)
	}

	// The scan page gets neither list, only whether an SBOM can be downloaded.
	detail := request(t, s, http.MethodGet, "/api/scans/"+scan.ID, nil)
	body := detail.Body.String()
	if detail.Code != http.StatusOK || strings.Contains(body, "installed_packages") || strings.Contains(body, "package-lock.json") ||
		!strings.Contains(body, `"sbom_available":true`) || !strings.Contains(body, `"count":1`) {
		t.Fatalf("scan detail = %d %s", detail.Code, body)
	}

	cdx := request(t, s, http.MethodGet, "/api/scans/"+scan.ID+"/sbom", nil)
	if cdx.Code != http.StatusOK || cdx.Header().Get("Content-Type") != "application/vnd.cyclonedx+json" ||
		!strings.Contains(cdx.Header().Get("Content-Disposition"), "deaconguard-web-01-20261018-100000.cdx.json") {
		t.Fatalf("CycloneDX = %d %v %s", cdx.Code, cdx.Header(), cdx.Body.String())
	}
	var bom struct {
		Components []struct{ Purl string }
	}
	json.Unmarshal(cdx.Body.Bytes(), &bom)
	if len(bom.Components) != 2 || bom.Components[1].Purl != "pkg:npm/lodash@4.17.21" {
		t.Errorf("components = %+v", bom.Components)
	}

	spdx := request(t, s, http.MethodGet, "/api/scans/"+scan.ID+"/sbom?format=spdx", nil)
	if spdx.Code != http.StatusOK || spdx.Header().Get("Content-Type") != "application/spdx+json" || !strings.Contains(spdx.Body.String(), `"SPDX-2.3"`) {
		t.Fatalf("SPDX = %d %s", spdx.Code, spdx.Body.String())
	}
	if bad := request(t, s, http.MethodGet, "/api/scans/"+scan.ID+"/sbom?format=xml", nil); bad.Code != http.StatusBadRequest {
		t.Errorf("unknown format = %d", bad.Code)
	}

	old, _ := store.CreateScan(host, []string{store.CheckPackages})
	store.CompleteScan(old.ID, map[string]any{"host_id": host.ID, "findings": []any{}})
	if missing := request(t, s, http.MethodGet, "/api/scans/"+old.ID+"/sbom", nil); missing.Code != http.StatusNotFound ||
		!strings.Contains(missing.Body.String(), "1.1.0") {
		t.Errorf("scan without inventory = %d %s", missing.Code, missing.Body.String())
	}
}
