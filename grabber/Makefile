BINARY  = grab
CMD     = ./cmd/grab/
LDFLAGS = -s -w

.PHONY: build build-prod build-linux build-linux-arm build-windows \
        test clean deps fmt help

build:
	go build -o $(BINARY) $(CMD)

build-prod:
	go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY) $(CMD)

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-linux-amd64 $(CMD)

build-linux-arm:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY)-linux-arm64 $(CMD)

# Windows requires mingw: x86_64-w64-mingw32-gcc (CGO for embedded PCRE2)
build-windows:
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o $(BINARY).exe $(CMD)

test:
	go test ./...

clean:
	rm -f $(BINARY) $(BINARY)-* $(BINARY).exe
	rm -rf bin/

deps:
	go mod download && go mod tidy

fmt:
	go fmt ./...

help:
	@echo "Targets:"
	@echo "  build           Build for current platform"
	@echo "  build-prod      Build optimized for current platform"
	@echo "  build-linux     Cross-compile Linux AMD64"
	@echo "  build-linux-arm Cross-compile Linux ARM64"
	@echo "  build-windows   Cross-compile Windows AMD64 (requires mingw)"
	@echo "  test            Run tests"
	@echo "  clean           Remove build artifacts"
	@echo "  deps            Download and tidy dependencies"
	@echo "  fmt             Format code"
