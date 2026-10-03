# syntax=docker/dockerfile:1.7
# Build stages run on the BUILD platform and cross-compile (CGO is off), so a
# multi-arch release does not compile under QEMU emulation.
# The UI is only BUILT here; its unit tests run on Node 22 (web/.nvmrc) in CI.
FROM --platform=$BUILDPLATFORM node:26-alpine AS web
WORKDIR /web
COPY web/package*.json ./
RUN --mount=type=cache,target=/root/.npm if [ -f package.json ]; then npm ci; fi
COPY web/ ./
RUN if [ -f package.json ]; then npm run build; else mkdir -p dist; fi

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web /web/dist ./internal/api/ui/dist
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/deckard ./cmd/deckard \
 && mkdir -p /out/var/lib/deckard

# nuclei is built from a pinned tag with the same (patched) Go toolchain as
# deckard instead of copying the upstream image, so its standard-library fixes
# track ours. Transitive dependencies with published security fixes are bumped.
# NUCLEI_VERSION is bumped by .github/workflows/nuclei-bump.yml. NUCLEI_GO_GET_PINS
# holds the transitive-dependency fixes; that workflow also builds with the pins
# emptied and, when Trivy stays clean, opens a PR that removes the obsolete ones.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS nuclei
ARG BUILDOS
ARG BUILDARCH
ARG TARGETOS
ARG TARGETARCH
ARG NUCLEI_VERSION=v3.11.1
ARG NUCLEI_GO_GET_PINS="golang.org/x/crypto@v0.55.0 golang.org/x/mod@v0.40.0 google.golang.org/grpc@v1.83.2 github.com/go-git/go-git/v5@v5.19.2"
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --quiet --depth 1 --branch ${NUCLEI_VERSION} https://github.com/projectdiscovery/nuclei.git .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    if [ -n "${NUCLEI_GO_GET_PINS}" ]; then go get ${NUCLEI_GO_GET_PINS}; fi \
 && go mod tidy -e \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w" -o /out/nuclei ./cmd/nuclei \
 && CGO_ENABLED=0 GOOS=${BUILDOS} GOARCH=${BUILDARCH} go build -trimpath -ldflags "-s -w" -o /out/nuclei-host ./cmd/nuclei

# The full image carries a reproducible cold-start snapshot. Download the exact
# tagged archive and verify its digest: asking nuclei for "latest" would make an
# unchanged Dockerfile fail as soon as ProjectDiscovery publishes a new tag.
# Validation uses the BUILD-platform binary so multi-architecture release builds
# never try to execute the TARGET-platform binary in this stage.
FROM --platform=$BUILDPLATFORM alpine:3.24 AS nuclei-templates
ARG NUCLEI_TEMPLATES_VERSION=v10.4.9
ARG NUCLEI_TEMPLATES_SHA256=d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6
COPY --from=nuclei /out/nuclei-host /usr/local/bin/nuclei
RUN mkdir -p /out/home /out/templates /download \
 && wget -q -O /download/templates.tar.gz \
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
 && echo "${NUCLEI_TEMPLATES_SHA256}  /download/templates.tar.gz" | sha256sum -c - \
 && tar -xzf /download/templates.tar.gz -C /out/templates --strip-components=1 \
 && test "$(find /out/templates -type f \( -name '*.yaml' -o -name '*.yml' \) | wc -l)" -ge 1000 \
 && test "$(find /out/templates/http -type f \( -name '*.yaml' -o -name '*.yml' \) | wc -l)" -ge 100 \
 && test "$(find /out/templates -type f | wc -l)" -le 200000 \
 && test "$(du -sk /out/templates | awk '{print $1}')" -le 524288 \
 && test -z "$(find /out/templates -type l -o -type c -o -type b -o -type p -o -type s)"
COPY templates/deckard /out/templates/deckard
RUN HOME=/out/home XDG_CONFIG_HOME=/out/home/config NUCLEI_CONFIG_DIR=/out/home/config/nuclei \
    NUCLEI_TEMPLATES_DIR=/out/templates \
    /usr/local/bin/nuclei -validate -duc \
      -t /out/templates/http -t /out/templates/ssl -t /out/templates/dns -t /out/templates/network -t /out/templates/deckard \
 && test "$(find /out/templates -type f \( -name '*.yaml' -o -name '*.yml' \) | wc -l)" -le 200000

# An empty state directory for the nuclei template updater. distroless has no
# shell, so the directory is prepared here and copied with its ownership.
FROM --platform=$BUILDPLATFORM alpine:3.24 AS state
RUN mkdir -p /state/var/lib/deckard/nuclei-templates

# slim: deckard only (no nuclei; set nuclei.enabled=false). Build with --target slim.
FROM gcr.io/distroless/static-debian12:nonroot AS slim
COPY --from=build /out/deckard /usr/local/bin/deckard
# Writable state dir (refdata/, vulnintel/ and, in full, nuclei-templates/),
# owned by nonroot so a mounted volume inherits usable permissions.
COPY --from=build --chown=65532:65532 /out/var/lib/deckard /var/lib/deckard
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/deckard"]
CMD ["serve"]

# full (default): deckard plus the nuclei engine for the cve.nuclei check.
# /var/lib/deckard is the template updater's writable state (nuclei.update.dir,
# default /var/lib/deckard/nuclei-templates), owned by the non-root user so a
# named volume or emptyDir mounted there is writable while the root filesystem
# stays read-only. HOME points at the always-writable /tmp tmpfs for any nuclei
# run that does not use the updater's own per-run directories.
FROM slim AS full
ARG NUCLEI_TEMPLATES_VERSION=v10.4.9
ARG NUCLEI_TEMPLATES_SHA256=d7cd989935f9a84943cba8a193f567db37626dbf4e526ff57ba5b1f24badd5d6
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
COPY --from=nuclei-templates --chown=65532:65532 /out/templates /usr/local/share/deckard/nuclei-templates
COPY --from=state --chown=65532:65532 /state/var/lib/deckard /var/lib/deckard
ENV HOME=/tmp
LABEL org.opencontainers.image.nuclei.templates="${NUCLEI_TEMPLATES_VERSION}" \
      org.opencontainers.image.nuclei.templates.digest="sha256:${NUCLEI_TEMPLATES_SHA256}"
