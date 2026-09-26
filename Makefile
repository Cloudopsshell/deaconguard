IMAGE ?= opsarmor:dev

.PHONY: ui ui-dev build test vet release-snapshot docker-build helm-lint helm-template clean

ui:
	cd web && npm ci && npm run build

# Runs the React dev server on :5173 with hot reload; start `./opsarmor serve` alongside it.
ui-dev:
	cd web && npm run dev

build: ui
	go build -trimpath -ldflags="-s -w" -o opsarmor ./cmd/opsarmor

test:
	go test ./...

vet:
	go vet ./...

release-snapshot:
	goreleaser release --snapshot --clean

docker-build:
	docker buildx build -t $(IMAGE) --load .

helm-lint:
	helm lint charts/opsarmor -f charts/opsarmor/values.example.yaml

helm-template:
	helm template opsarmor charts/opsarmor -f charts/opsarmor/values.example.yaml

clean:
	rm -f opsarmor
	rm -rf dist