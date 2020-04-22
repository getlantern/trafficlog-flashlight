
TLSERVER_DIR := internal/cmd/tlserver
TLSERVER_SRCS := $(shell find $(TLSERVER_DIR) -name "*.go") go.mod go.sum
BIN_DIR := $(TLSERVER_DIR)/binaries
EMBED_DIR := internal/tlserverbin

all: $(EMBED_DIR)/*
.PHONY: test

$(BIN_DIR)/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/darwin/amd64/tlserver \
		./$(TLSERVER_DIR)

$(BIN_DIR)/debug/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/debug/darwin/amd64/tlserver \
		-tags debug \
		./$(TLSERVER_DIR)

$(EMBED_DIR)/tlsb_darwin_amd64.go: $(BIN_DIR)/darwin/amd64/tlserver
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_darwin_amd64.go \
		-prefix $(BIN_DIR)/darwin/amd64 \
		-tags !debug \
		$(BIN_DIR)/darwin/amd64

$(EMBED_DIR)/tlsb_debug_darwin_amd64.go: $(BIN_DIR)/debug/darwin/amd64/tlserver
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_debug_darwin_amd64.go \
		-prefix $(BIN_DIR)/debug/darwin/amd64 \
		-tags debug \
		$(BIN_DIR)/debug/darwin/amd64

tlproc/tlproc.test: $(EMBED_DIR)/* $(shell find . -name *.go) go.mod go.sum
	@go test -c -o ./tlproc/tlproc.test -tags debug ./tlproc

test: tlproc/tlproc.test
	@echo "These tests require elevated permissions; you may be prompted for your password."
	@sudo ./tlproc/tlproc.test -elevated
