
TLSERVER_DIR := internal/cmd/tlserver
TLSERVER_SRCS := $(shell find $(TLSERVER_DIR) -name "*.go") go.mod go.sum
BIN_DIR := $(TLSERVER_DIR)/binaries
EMBED_DIR := internal/tlserverbin
STAGING_DIR := build-staging
TLCONFIG := $(STAGING_DIR)/tlconfig

all: $(EMBED_DIR)/*
.PHONY: test clean

# TODO: embedded binaries need to be signed

$(STAGING_DIR):
	@mkdir $(STAGING_DIR)

$(TLCONFIG): $(shell find internal/cmd/tlconfig -name "*.go") $(STAGING_DIR)
	go build -o $(TLCONFIG) ./internal/cmd/tlconfig

$(BIN_DIR)/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/darwin/amd64/tlserver \
		./$(TLSERVER_DIR)

$(BIN_DIR)/debug/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/debug/darwin/amd64/tlserver \
		-tags debug \
		./$(TLSERVER_DIR)

$(EMBED_DIR)/tlsb_darwin_amd64.go: $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR) $(TLCONFIG)
	@cp $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR)
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_darwin_amd64.go \
		-prefix $(STAGING_DIR) \
		-tags !debug \
		$(STAGING_DIR)

$(EMBED_DIR)/tlsb_debug_darwin_amd64.go: $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR) $(TLCONFIG)
	@cp $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR)
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_debug_darwin_amd64.go \
		-prefix $(STAGING_DIR) \
		-tags debug \
		$(STAGING_DIR)

test:
	@go test -race -tags debug ./tlproc

clean:
	@rm -r $(STAGING_DIR) 2> /dev/null || true
