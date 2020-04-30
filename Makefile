
TLSERVER_DIR := internal/cmd/tlserver
TLSERVER_SRCS := $(shell find $(TLSERVER_DIR) -name "*.go") go.mod go.sum
BIN_DIR := $(TLSERVER_DIR)/binaries
SCRIPTS_DIR := internal/embedded_scripts
SCRIPTS := $(shell find $(SCRIPTS_DIR) -type f -name "*")
EMBED_DIR := internal/tlserverbin
STAGING_DIR := staging

all: $(EMBED_DIR)/*
.PHONY: test

# TODO: embedded binaries need to be signed

$(BIN_DIR)/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/darwin/amd64/tlserver \
		./$(TLSERVER_DIR)

$(BIN_DIR)/debug/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/debug/darwin/amd64/tlserver \
		-tags debug \
		./$(TLSERVER_DIR)

$(EMBED_DIR)/tlsb_darwin_amd64.go: $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR) $(SCRIPTS)
	@cp $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR)/tlserver
	@cp $(SCRIPTS_DIR)/darwin/install_tlserver.sh $(STAGING_DIR)/install_tlserver.sh
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_darwin_amd64.go \
		-prefix $(STAGING_DIR) \
		-tags !debug \
		$(STAGING_DIR)

$(EMBED_DIR)/tlsb_debug_darwin_amd64.go: $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR) $(SCRIPTS)
	@cp $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR)/tlserver
	@cp $(SCRIPTS_DIR)/darwin/install_tlserver.sh $(STAGING_DIR)/install_tlserver.sh
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

$(STAGING_DIR):
	@mkdir $(STAGING_DIR)
