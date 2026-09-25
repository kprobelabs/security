# SPiCa Makefile
# Run `make install-deps` and `make install-tools` once, then `make all` to build, `make run` to detect.
# `make build` is self-contained: build.rs generates the XOR key and compiles the eBPF probe in one step.

.PHONY: help install-deps install-tools generate-vmlinux build-ebpf build all run clean

# Default target
help:
	@echo "SPiCa — build targets:"
	@echo ""
	@echo "  install-deps       Install system dependencies (requires root)"
	@echo "  install-tools      Install bpf-linker and aya-tool (run once)"
	@echo "  generate-vmlinux   Generate BTF bindings for running kernel (run once per kernel update)"
	@echo "  build-ebpf         Compile the eBPF kernel probe (dev/check only)"
	@echo "  build              Compile everything: generates key, compiles eBPF + userspace"
	@echo "  all                Full pipeline: generate-vmlinux → build"
	@echo "  run                Run SPiCa (requires root)"
	@echo "  clean              Remove build artifacts"
	@echo ""
	@echo "  Typical setup:"
	@echo "    make install-deps"
	@echo "    make install-tools"
	@echo "    make all"
	@echo "    make run"

install-deps:
	@if command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S --needed --noconfirm base-devel clang llvm libelf bpf; \
	elif command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y build-essential clang llvm libelf-dev linux-tools-common bpftool; \
	elif command -v dnf >/dev/null 2>&1; then \
		sudo dnf install -y clang llvm elfutils-libelf-devel bpftool; \
	else \
		echo "Unsupported package manager. Install clang, llvm, libelf, and bpftool manually."; \
		exit 1; \
	fi
	rustup toolchain install nightly --component rust-src
	rustup override set nightly

install-tools:
	cargo install bpf-linker
	cargo install --git https://github.com/aya-rs/aya aya-tool

generate-vmlinux:
	cargo run --package xtask generate-vmlinux

build-ebpf:
	cargo run --package xtask build-ebpf --release

build:
	cargo build --release

all: generate-vmlinux build

run:
	sudo ./target/release/spica

clean:
	cargo clean
