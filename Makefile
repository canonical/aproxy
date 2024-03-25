# Makefile for building aproxy

# Go compiler
GO := go

# Output directory
OUT_DIR := out

# Binary name
BINARY_NAME := aproxy

LOCAL_ARCH := $(shell go env GOARCH)

# Flags for the Go build command
GO_BUILD_FLAGS := -v

# Default target
.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help message
	@echo "Usage: make [target]"
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the Go binary for the specified architecture (e.g., make build ARCH=amd64)
	@if [ -z "$(ARCH)" ]; then \
		echo "ARCH is not set. Using local architecture: $(LOCAL_ARCH)"; \
		GOARCH=$(LOCAL_ARCH) $(GO) build $(GO_BUILD_FLAGS) -o $(OUT_DIR)/$(BINARY_NAME).$(LOCAL_ARCH); \
	else \
		echo "Using specified architecture: $(ARCH)"; \
		GOARCH=$(ARCH) $(GO) build $(GO_BUILD_FLAGS) -o $(OUT_DIR)/$(BINARY_NAME).$(ARCH); \
	fi

.PHONY: rpm
rpm: ## Build the RPM package for the specified architecture (e.g., make rpm ARCH=amd64)
	@if [ -z "$(ARCH)" ]; then \
	    echo "ARCH is not set. Using local architecture: $(LOCAL_ARCH)"; \
	    ARCH="$(LOCAL_ARCH)"; \
	elif [ "$(ARCH)" = "arm64" ]; then \
	    echo "Copying .arm64 binary to .aarch64"; \
	    cp $(OUT_DIR)/$(BINARY_NAME).arm64 $(OUT_DIR)/$(BINARY_NAME).aarch64; \
	    rpmbuild -bb --define "_topdir $(PWD)/rpmbuild" --define "ARCH aarch64" --define "VERSION $(VERSION)" --target aarch64 aproxy.spec; \
	else \
	    echo "Using specified architecture: $(ARCH)"; \
	    rpmbuild -bb --define "_topdir $(PWD)/rpmbuild" --define "ARCH $(ARCH)" --define "VERSION $(VERSION)" --target "$(ARCH)" aproxy.spec; \
	fi


.PHONY: clean
clean: ## Clean the build artifacts
	rm -rf $(OUT_DIR)
	rm -rf rpmbuild

.PHONY: all
all: clean build rpm ## Build all binaries
