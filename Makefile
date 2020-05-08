
TLSERVER_DIR := internal/cmd/tlserver
TLSERVER_SRCS := $(shell find $(TLSERVER_DIR) -name "*.go") go.mod go.sum
BIN_DIR := $(TLSERVER_DIR)/binaries
EMBED_DIR := internal/tlserverbin
STAGING_DIR := build-staging
DARWIN_INSTALLER := $(STAGING_DIR)/installer

all: $(EMBED_DIR)/*
.PHONY: test clean

# TODO: embedded binaries need to be signed

$(STAGING_DIR):
	@mkdir $(STAGING_DIR)

$(DARWIN_INSTALLER): $(shell find internal/cmd/installer -name "*.go") $(STAGING_DIR)
	go build -o $(DARWIN_INSTALLER) ./internal/cmd/installer

$(BIN_DIR)/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/darwin/amd64/tlserver \
		./$(TLSERVER_DIR)

$(BIN_DIR)/debug/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/debug/darwin/amd64/tlserver \
		-tags debug \
		./$(TLSERVER_DIR)

$(EMBED_DIR)/tlsb_darwin_amd64.go: $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR) $(DARWIN_INSTALLER)
	@cp $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR)
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_darwin_amd64.go \
		-prefix $(STAGING_DIR) \
		-tags !debug \
		$(STAGING_DIR)

$(EMBED_DIR)/tlsb_debug_darwin_amd64.go: $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR) $(DARWIN_INSTALLER)
	@cp $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR)
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_debug_darwin_amd64.go \
		-prefix $(STAGING_DIR) \
		-tags debug \
		$(STAGING_DIR)

tlproc/tlproc.test: $(EMBED_DIR)/* $(shell find . -name *.go) go.mod go.sum
	@go test -race -c -o ./tlproc/tlproc.test -tags debug ./tlproc

test: tlproc/tlproc.test
	@echo "These tests require elevated permissions; you may be prompted for your password."
	@sudo ./tlproc/tlproc.test -elevated

clean:
	@rm -r $(STAGING_DIR) 2> /dev/null || true
	@rm tlproc/tlproc.test 2> /dev/null || true
