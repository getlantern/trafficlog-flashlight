
TLSERVER_DIR := internal/cmd/tlserver
BIN_DIR := $(TLSERVER_DIR)/binaries
EMBED_DIR := internal/tlserverbin

all: $(EMBED_DIR)/*

$(BIN_DIR)/darwin/amd64/tlserver: $(shell find $(TLSERVER_DIR) -name "*.go") go.mod go.sum
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/darwin/amd64/tlserver \
		./$(TLSERVER_DIR)

$(EMBED_DIR)/tlsb_darwin_amd64.go: $(BIN_DIR)/darwin/amd64/tlserver
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_darwin_amd64.go \
		-prefix $(BIN_DIR)/darwin/amd64 \
		$(BIN_DIR)/darwin/amd64
