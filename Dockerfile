# Runtime-only image — uses pre-built binaries from CI, no compilation.
# Build context must contain:
#   bin/tirith   — the pre-built binary for the target platform
#   shell/       — shell hook scripts
# Pinned by digest (repo-0443): a movable tag could silently swap the base
# image for attacker-controlled content. Refresh the digest regularly (e.g.
# via Dependabot/Renovate) to keep receiving Debian security updates.
# Digest source: registry-1.docker.io manifest list for debian:bookworm-slim.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --user-group tirith

COPY bin/tirith /usr/local/bin/tirith
COPY shell /usr/share/tirith/shell

RUN chmod +x /usr/local/bin/tirith

USER tirith

ENTRYPOINT ["tirith"]
CMD ["--help"]
