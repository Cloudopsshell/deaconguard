FROM --platform=$BUILDPLATFORM node:24-alpine AS ui

WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=
ARG DATE=

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web ./web
COPY --from=ui /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags="-s -w -X deaconguard/internal/buildinfo.Version=${VERSION} -X deaconguard/internal/buildinfo.Commit=${COMMIT} -X deaconguard/internal/buildinfo.Date=${DATE}" \
      -o /out/deaconguard ./cmd/deaconguard \
    && mkdir -p /out/rootfs/data /out/rootfs/tmp \
    && chown -R 65532:65532 /out/rootfs \
    && chmod 1777 /out/rootfs/tmp

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder --chown=65532:65532 /out/deaconguard /usr/local/bin/deaconguard
COPY --from=builder --chown=65532:65532 /out/rootfs/data /data
COPY --from=builder --chown=65532:65532 /out/rootfs/tmp /tmp

ENV HOME=/home/nonroot \
    DEACONGUARD_HOME=/data

VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/deaconguard"]