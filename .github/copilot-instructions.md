# OpsArmor development

OpsArmor is a Go CLI that scans explicitly registered remote Linux hosts over SSH. The controller does not scan itself. Keep remote commands limited to fixed inventory reads in `internal/remote`, enforce SSH known-host verification, and never persist private key material. A failed or incomplete scan must not return an empty clean report.

Build with `go build ./cmd/opsarmor`; run `go test ./...` and `go vet ./...`. Only enable a platform when its official advisory source and evaluator are verified. Unsupported advisory rules must be reported, never counted as clean.