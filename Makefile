IMAGE ?= opsarmor:dev

.PHONY: build test vet release-snapshot docker-build helm-lint helm-template clean

build:
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