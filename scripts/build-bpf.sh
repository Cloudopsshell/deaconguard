#!/bin/sh
# Builds live detection's kernel programs, internal/live/bpf/watch.c, into
# internal/live/watch.o, which the agent embeds, and records the source's
# SHA-256 in internal/live/watch.sum so a test can tell when the object is
# out of date. Needs Docker; the compiler runs in a pinned Debian image.
#
#   sh scripts/build-bpf.sh
set -eu
cd "$(dirname "$0")/.."
image=debian:12@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880
docker run --rm -v "$PWD/internal/live:/live" -w /live "$image" sh -c '
	apt-get -qq update >/dev/null && apt-get -qq install -y --no-install-recommends clang llvm >/dev/null &&
	clang -O2 -g0 -target bpfel -Wall -Werror -c bpf/watch.c -o watch.o &&
	llvm-strip -g watch.o'
sha256sum internal/live/bpf/watch.c 2>/dev/null | cut -d" " -f1 > internal/live/watch.sum || shasum -a 256 internal/live/bpf/watch.c | cut -d" " -f1 > internal/live/watch.sum
echo "Built internal/live/watch.o from $(cat internal/live/watch.sum)"
