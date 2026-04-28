# Aegis-eBPF SDK — Build & Test Makefile

CRATE_DIR    := .
TARGET_DIR   := ../target/debug
LIB_NAME     := aegis_ebpf
INCLUDE_DIR  := include
EXAMPLES_DIR := examples

CC      := cc
CFLAGS  := -Wall -Wextra -std=c11 -g
LDFLAGS := $(TARGET_DIR)/libaegis_ebpf.a -ldl -lpthread -lm -lgcc_s

.PHONY: all build header c-test rust-test clean

## Build everything
all: build header c-test

## Build the Rust crate (generates header via build.rs)
build:
	cargo build

## Explicitly regenerate the C header
header: build
	@echo "Header generated at $(INCLUDE_DIR)/aegis.h"
	@sed -n '1,20p' $(INCLUDE_DIR)/aegis.h

## Compile and run the C smoke test (statically linked to libaegis_ebpf.a)
c-test: build
	$(CC) $(CFLAGS) \
	    -o $(TARGET_DIR)/c_smoke_test \
	    $(EXAMPLES_DIR)/c_smoke_test.c \
	    -I$(INCLUDE_DIR) \
	    $(LDFLAGS)
	$(TARGET_DIR)/c_smoke_test

## Run Rust tests
rust-test:
	cargo test --all-features

## Clean build artifacts
clean:
	cargo clean
	rm -f $(TARGET_DIR)/c_smoke_test
