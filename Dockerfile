# syntax=docker/dockerfile:1.7

# Build static web assets natively, independently of the target image architecture.
FROM --platform=$BUILDPLATFORM node:22.18.0-alpine3.22 AS web-build
WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY apps/web ./
RUN npm run build

# Run the Go toolchain natively and cross-compile with TARGETOS/TARGETARCH below.
FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
# Bound compiler concurrency and Go heap growth for the large cloud SDK packages.
# GOMEMLIMIT is a soft limit per Go process, not a container memory limit.
ARG GO_BUILD_PARALLELISM=1
ARG GO_BUILD_GOGC=50
ARG GO_BUILD_GOMAXPROCS=1
ARG GO_BUILD_GOMEMLIMIT=1GiB
ENV GOFLAGS="-p=${GO_BUILD_PARALLELISM}" \
    GOMAXPROCS=${GO_BUILD_GOMAXPROCS} \
    GOGC=${GO_BUILD_GOGC} \
    GOMEMLIMIT=${GO_BUILD_GOMEMLIMIT}
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    printf 'Go build: target=%s/%s GOFLAGS=%s GOMAXPROCS=%s GOGC=%s GOMEMLIMIT=%s\n' \
        "$TARGETOS" "$TARGETARCH" "$GOFLAGS" "$GOMAXPROCS" "$GOGC" "$GOMEMLIMIT" && \
    awk '/^Mem(Total|Available):/ { print }' /proc/meminfo && \
    for limit_file in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory/memory.limit_in_bytes; do \
        if [ -r "$limit_file" ]; then printf '%s=' "$limit_file"; cat "$limit_file"; fi; \
    done && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/access-gateway ./cmd/access-gateway && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/gateway-agent ./cmd/gateway-agent && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/migrate ./cmd/migrate && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/audit-collector ./cmd/audit-collector && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/catalog-release ./cmd/catalog-release && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags='-s -w' -o /out/account ./cmd/account

# Native web clients run in the session worker from the same application image.
# MongoDB's official multi-architecture image supplies its glibc-based shell.
FROM mongo:8.0-noble AS mongo-client
FROM ubuntu:24.04 AS access-gateway
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates mariadb-client postgresql-client redis-tools curl bash libssl3t64 && \
    # bash is here only for the sandboxed HTTP terminal, whose Landlock policy
    # does not grant /etc. Leaving the distribution rc file in place would make
    # every session open with "bash: /etc/bash.bashrc: Permission denied";
    # removing it lets bash skip the file silently instead.
    rm -f /etc/bash.bashrc && \
    groupadd --gid 65532 nonroot && \
    useradd --uid 65532 --gid 65532 --no-create-home --home-dir /tmp --shell /usr/sbin/nologin nonroot && \
    rm -rf /var/lib/apt/lists/*
COPY --from=mongo-client /usr/bin/mongosh /usr/bin/mongosh
RUN mariadb --version && psql --version && redis-cli --version && mongosh --version && curl --version
ENV GATEWAY_RUNTIME=docker \
    WEB_ASSETS_DIR=/usr/local/share/access-gateway-web
COPY --from=build --chown=nonroot:nonroot /out/access-gateway /usr/local/bin/access-gateway
COPY --from=build --chown=nonroot:nonroot /out/gateway-agent /usr/local/bin/gateway-agent
COPY --from=build --chown=nonroot:nonroot /out/migrate /usr/local/bin/migrate
COPY --from=build --chown=nonroot:nonroot /out/account /usr/local/bin/account
COPY --from=build --chown=nonroot:nonroot /out/audit-collector /usr/local/bin/audit-collector
COPY --from=build --chown=nonroot:nonroot /out/catalog-release /usr/local/bin/catalog-release
COPY --from=web-build --chown=nonroot:nonroot /src/apps/web/dist /usr/local/share/access-gateway-web
USER nonroot:nonroot
EXPOSE 8080 8090 20000-20999
ENTRYPOINT ["/usr/local/bin/access-gateway"]
CMD []
