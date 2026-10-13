VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
TARGET ?= x86_64-unknown-linux-gnu

.PHONY: all ui build test integration demo dist clean fmt lint

all: ui build

ui:
	cd web && npm ci && npm run build

build:
	FSVIEW_VERSION=$(VERSION) cargo build --release --locked --target $(TARGET) --bin fsview
	mkdir -p bin && cp target/$(TARGET)/release/fsview bin/fsview

test:
	cargo fmt --check
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --locked
	cd web && npm run typecheck

# Needs root and loop devices. Only temporary loop devices are touched.
integration:
	sudo -E env "PATH=$$PATH" cargo test --locked --features integration --test integration -- --test-threads=1

# UI against recorded spiritlab fixtures: http://127.0.0.1:9201 (demo / demo-password)
demo:
	cargo run --bin fsview-demo

dist: ui build
	rm -rf dist/fsview-$(VERSION)-linux-amd64
	mkdir -p dist/fsview-$(VERSION)-linux-amd64
	cp bin/fsview deploy/install.sh deploy/uninstall.sh deploy/fsview.conf deploy/helper.conf dist/fsview-$(VERSION)-linux-amd64/
	cp -r deploy/systemd dist/fsview-$(VERSION)-linux-amd64/
	tar -C dist -czf dist/fsview-$(VERSION)-linux-amd64.tar.gz fsview-$(VERSION)-linux-amd64

fmt:
	cargo fmt

clean:
	cargo clean
	rm -rf bin dist
