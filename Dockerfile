# syntax=docker/dockerfile:1.7
FROM node:26-alpine AS web
WORKDIR /web
COPY web/package*.json ./
RUN --mount=type=cache,target=/root/.npm if [ -f package.json ]; then npm ci; fi
COPY web/ ./
RUN if [ -f package.json ]; then npm run build; else mkdir -p dist; fi

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web /web/dist ./internal/api/ui/dist
ARG VERSION=dev
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/deckard ./cmd/deckard \
 && mkdir -p /out/var/lib/deckard

# nuclei is built from a pinned tag with the same (patched) Go toolchain as
# deckard instead of copying the upstream image, so its standard-library fixes
# track ours. Transitive dependencies with published security fixes are bumped.
# NUCLEI_VERSION is bumped by .github/workflows/nuclei-bump.yml. NUCLEI_GO_GET_PINS
# holds the transitive-dependency fixes; that workflow also builds with the pins
# emptied and, when Trivy stays clean, opens a PR that removes the obsolete ones.
FROM golang:1.27-alpine AS nuclei
ARG NUCLEI_VERSION=v3.11.1
ARG NUCLEI_GO_GET_PINS="golang.org/x/crypto@v0.55.0 golang.org/x/mod@v0.40.0 google.golang.org/grpc@v1.83.2 github.com/go-git/go-git/v5@v5.19.2"
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --quiet --depth 1 --branch ${NUCLEI_VERSION} https://github.com/projectdiscovery/nuclei.git .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    if [ -n "${NUCLEI_GO_GET_PINS}" ]; then go get ${NUCLEI_GO_GET_PINS}; fi \
 && go mod tidy -e \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/nuclei ./cmd/nuclei

# An empty state directory for the nuclei template updater. distroless has no
# shell, so the directory is prepared here and copied with its ownership.
FROM alpine:3.24 AS state
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
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
COPY --from=state --chown=65532:65532 /state/var/lib/deckard /var/lib/deckard
ENV HOME=/tmp
