MODULES = synscan grabber datastore

.PHONY: build build-prod build-linux build-linux-arm build-darwin build-darwin-arm \
        build-windows build-windows-arm \
        build-synscan build-grabber build-datastore \
        test clean deps fmt dist help

# All modules
build:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build; done

build-prod:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build-prod; done

build-linux:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build-linux; done

build-linux-arm:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build-linux-arm; done

build-darwin:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build-darwin; done

build-darwin-arm:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build-darwin-arm; done

# Note: grabber requires mingw x86_64-w64-mingw32-gcc (CGO for PCRE2)
build-windows:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build-windows; done

# Note: grabber requires mingw aarch64-w64-mingw32-gcc (CGO for PCRE2)
build-windows-arm:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod build-windows-arm; done

# Individual modules
build-synscan:
	$(MAKE) -C synscan build

build-grabber:
	$(MAKE) -C grabber build

build-datastore:
	$(MAKE) -C datastore build

# Cross-compile all platforms via Docker (output in ./dist)
dist:
	DOCKER_BUILDKIT=1 docker build --output=type=local,dest=. .

# Quality
test:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod test; done

fmt:
	@for mod in $(MODULES); do echo "==> $$mod"; $(MAKE) -C $$mod fmt; done

clean:
	@for mod in $(MODULES); do $(MAKE) -C $$mod clean; done
	rm -rf dist/

deps:
	@for mod in $(MODULES); do $(MAKE) -C $$mod deps; done

help:
	@echo "Targets:"
	@echo "  build             Build all modules"
	@echo "  build-prod        Build all optimized"
	@echo "  build-linux       Cross-compile all Linux AMD64"
	@echo "  build-linux-arm   Cross-compile all Linux ARM64"
	@echo "  build-darwin      Cross-compile all macOS AMD64"
	@echo "  build-darwin-arm  Cross-compile all macOS ARM64 (Apple Silicon)"
	@echo "  build-windows     Cross-compile all Windows AMD64 (grabber needs x86_64-w64-mingw32-gcc)"
	@echo "  build-windows-arm Cross-compile all Windows ARM64 (grabber needs aarch64-w64-mingw32-gcc)"
	@echo "  build-synscan     Build synscan only"
	@echo "  build-grabber     Build grabber only"
	@echo "  build-datastore   Build datastore only"
	@echo "  dist              Build all platforms via Docker (-> ./dist/)"
	@echo "  test              Run all tests"
	@echo "  fmt               Format all code"
	@echo "  clean             Clean all build artifacts"
	@echo "  deps              Download all dependencies"
