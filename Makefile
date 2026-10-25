GO ?= go

.PHONY: all build generate test vet clean
all: build

# Regenerate internal/datapath/mux.o from bpf/mux.c.
# Requires: clang, libbpf headers (Debian/Ubuntu: clang llvm libbpf-dev).
generate:
	$(GO) generate ./internal/datapath/

build: generate
	$(GO) build -o bin/wgmux ./cmd/wgmux

# Build without regenerating the BPF object (uses the committed mux.o).
build-committed:
	$(GO) build -o bin/wgmux ./cmd/wgmux

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf bin
