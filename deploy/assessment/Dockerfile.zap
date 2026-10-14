# syntax=docker/dockerfile:1.7
ARG DECKARD_IMAGE
FROM ${DECKARD_IMAGE} AS deckard

# Official ZAP 2.17.0 multi-architecture snapshot, verified before integration.
FROM ghcr.io/zaproxy/zaproxy@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2 AS scanner

# Headless native automation needs Java, not the upstream Python wrappers,
# browsers or Webswing server. Do not ship their unused vulnerable dependencies.
FROM debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# Debian security updates are chosen at build; scan/sign/pin the resulting image.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates openjdk-17-jre-headless perl-base \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY --from=scanner /zap/db /zap/db
COPY --from=scanner /zap/lang /zap/lang
COPY --from=scanner /zap/lib /zap/lib
COPY --from=scanner /zap/license /zap/license
COPY --from=scanner /zap/plugin /zap/plugin
COPY --from=scanner /zap/xml /zap/xml
COPY --from=scanner /zap/zap.sh /zap/zap-2.17.0.jar /zap/README /zap/CHANGELOG.md /zap/
COPY --from=deckard /usr/local/bin/deckard /usr/local/bin/deckard
ENV HOME=/tmp/home
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/deckard"]
