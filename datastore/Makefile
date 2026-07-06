BINARY  = datastore
CMD     = ./cmd/datastore/
LDFLAGS = -s -w

.PHONY: build build-prod build-linux build-linux-arm build-darwin build-darwin-arm \
        build-windows build-windows-arm test clean deps fmt run run-dev help

build:
	go build -o $(BINARY) $(CMD)

build-prod:
	go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY) $(CMD)

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-linux-amd64 $(CMD)

build-linux-arm:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-linux-arm64 $(CMD)

build-darwin:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-darwin-amd64 $(CMD)

build-darwin-arm:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-darwin-arm64 $(CMD)

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY).exe $(CMD)

build-windows-arm:
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-arm64.exe $(CMD)

test:
	go test ./...

clean:
	rm -f $(BINARY) $(BINARY)-* $(BINARY).exe scanner.db scanner.db-*

deps:
	go mod download && go mod tidy

fmt:
	go fmt ./...

run:
	go run $(CMD) --debug

run-dev:
	go run $(CMD) --debug --api-port=8090

help:
	@echo "Targets:"
	@echo "  build             Build for current platform"
	@echo "  build-prod        Build optimized for current platform"
	@echo "  build-linux       Cross-compile Linux AMD64"
	@echo "  build-linux-arm   Cross-compile Linux ARM64"
	@echo "  build-darwin      Cross-compile macOS AMD64"
	@echo "  build-darwin-arm  Cross-compile macOS ARM64 (Apple Silicon)"
	@echo "  build-windows     Cross-compile Windows AMD64"
	@echo "  build-windows-arm Cross-compile Windows ARM64"
	@echo "  test              Run tests"
	@echo "  clean             Remove build artifacts"
	@echo "  deps              Download and tidy dependencies"
	@echo "  fmt               Format code"
	@echo "  run               Run with verbose logging"
	@echo "  run-dev           Run dev mode (no auth, port 8090)"
