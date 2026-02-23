# syntax=docker/dockerfile:1

# ──────────────────────────────────────────────
# Base: Go 1.24 + mingw for grabber Windows CGO
# ──────────────────────────────────────────────
FROM golang:1.24-bookworm AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc-mingw-w64-x86-64 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Deps cache (re-downloaded only when go.mod/go.sum change)
COPY synscan/go.mod  synscan/go.sum  ./synscan/
COPY grabber/go.mod  grabber/go.sum  ./grabber/
COPY datastore/go.mod datastore/go.sum ./datastore/
RUN cd synscan && go mod download && \
    cd ../grabber && go mod download && \
    cd ../datastore && go mod download

COPY . .

# ──────────────────────────────
# SynScan — no CGO, all platforms
# ──────────────────────────────
FROM base AS build-synscan
WORKDIR /src/synscan
RUN --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out/linux-amd64 /out/linux-arm64 /out/darwin-amd64 /out/darwin-arm64 /out/windows-amd64 && \
    GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/linux-amd64/synscan     ./cmd/synscan/ && \
    GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/linux-arm64/synscan     ./cmd/synscan/ && \
    GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/darwin-amd64/synscan    ./cmd/synscan/ && \
    GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/darwin-arm64/synscan    ./cmd/synscan/ && \
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/windows-amd64/synscan.exe ./cmd/synscan/

# ──────────────────────────────────────────────────────
# Grabber — pure Go on unix, CGO+mingw on Windows (PCRE2)
# ──────────────────────────────────────────────────────
FROM base AS build-grabber
WORKDIR /src/grabber
RUN --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out/linux-amd64 /out/linux-arm64 /out/darwin-amd64 /out/darwin-arm64 /out/windows-amd64 && \
    GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/linux-amd64/grab     ./cmd/grab/ && \
    GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/linux-arm64/grab     ./cmd/grab/ && \
    GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/darwin-amd64/grab    ./cmd/grab/ && \
    GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/darwin-arm64/grab    ./cmd/grab/ && \
    CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o /out/windows-amd64/grab.exe ./cmd/grab/

# ──────────────────────────────────────────────────────────
# Datastore — no CGO (modernc.org/sqlite is pure Go)
# ──────────────────────────────────────────────────────────
FROM base AS build-datastore
WORKDIR /src/datastore
RUN --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out/linux-amd64 /out/linux-arm64 /out/darwin-amd64 /out/darwin-arm64 /out/windows-amd64 && \
    GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/linux-amd64/datastore     ./cmd/datastore/ && \
    GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/linux-arm64/datastore     ./cmd/datastore/ && \
    GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/darwin-amd64/datastore    ./cmd/datastore/ && \
    GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/darwin-arm64/datastore    ./cmd/datastore/ && \
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /out/windows-amd64/datastore.exe ./cmd/datastore/

# ──────────────────────────────
# Output: only binaries in /dist
# ──────────────────────────────
FROM scratch
COPY --from=build-synscan   /out/ /dist/
COPY --from=build-grabber   /out/ /dist/
COPY --from=build-datastore /out/ /dist/
