IMAGE ?= deaconguard:dev
# The version comes from the nearest v* tag, such as v0.1.0 -> 0.1.0; untagged builds are "dev".
VERSION ?= $(shell git describe --tags --match 'v*' --dirty 2>/dev/null | sed 's/^v//' || true)
ifeq ($(VERSION),)
VERSION := dev
endif
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X deaconguard/internal/buildinfo.Version=$(VERSION) -X deaconguard/internal/buildinfo.Commit=$(COMMIT) -X deaconguard/internal/buildinfo.Date=$(DATE)

.PHONY: ui ui-dev build test vet release-snapshot docker-build clean

ui:
	cd web && npm ci && npm run build

# Runs the React dev server on :5173 with hot reload; start `./deaconguard serve` alongside it.
ui-dev:
	cd web && npm run dev

build: ui
	go build -trimpath -ldflags="$(LDFLAGS)" -o deaconguard ./cmd/deaconguard

test:
	go test ./...

vet:
	go vet ./...

release-snapshot:
	goreleaser release --snapshot --clean --skip=sign

docker-build:
	docker buildx build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(IMAGE) --load .

clean:
	rm -f deaconguard
	rm -rf dist