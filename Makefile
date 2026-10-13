VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
ARCH ?= amd64

.PHONY: all ui build test integration demo dist clean fmt

all: ui build

ui:
	cd web && npm ci && npm run build

build:
	CGO_ENABLED=0 GOARCH=$(ARCH) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/fsview ./cmd/fsview

test:
	go vet ./...
	test -z "$$(gofmt -l .)"
	go test ./...
	cd web && npm run typecheck

# Needs root and loop devices. Only temporary loop devices are touched.
integration:
	CGO_ENABLED=0 go test -c -tags integration -o bin/it.test ./test/integration
	sudo bin/it.test -test.v

# UI against recorded spiritlab fixtures: http://127.0.0.1:9201 (demo / demo-password)
demo:
	go run ./cmd/fsview-demo

dist: ui
	$(MAKE) build ARCH=$(ARCH)
	rm -rf dist/fsview-$(VERSION)-linux-$(ARCH)
	mkdir -p dist/fsview-$(VERSION)-linux-$(ARCH)
	cp bin/fsview deploy/install.sh deploy/uninstall.sh deploy/fsview.conf deploy/helper.conf dist/fsview-$(VERSION)-linux-$(ARCH)/
	cp -r deploy/systemd dist/fsview-$(VERSION)-linux-$(ARCH)/
	tar -C dist -czf dist/fsview-$(VERSION)-linux-$(ARCH).tar.gz fsview-$(VERSION)-linux-$(ARCH)

fmt:
	gofmt -w .

clean:
	rm -rf bin dist
