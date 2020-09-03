
TLSERVER_DIR := internal/cmd/tlserver
TLSERVER_SRCS := $(shell find $(TLSERVER_DIR) -name "*.go") go.mod go.sum
BIN_DIR := $(TLSERVER_DIR)/binaries
EMBED_DIR := internal/tlserverbin
STAGING_DIR := build-staging

# tlconfig and config-bpf are only built for macOS.
TLCONFIG := $(STAGING_DIR)/unsigned/tlconfig
TLCONFIG_SRCS := $(shell find internal/cmd/tlconfig internal/exitcodes -name "*.go") go.mod go.sum
CONFIG_BPF := $(STAGING_DIR)/unsigned/config-bpf
CONFIG_BPF_SRCS := $(shell find internal/cmd/config-bpf -name "*.go") go.mod go.sum

all: $(EMBED_DIR)/*
.PHONY: test clean debug

define osxcodesign
	codesign --options runtime --strict --timestamp --force \
		-r="designated => anchor trusted and identifier com.getlantern.lantern" \
		-s "Developer ID Application: Innovate Labs LLC (4FYC28AXA2)" \
		$(1)
endef

$(STAGING_DIR):
	@mkdir $(STAGING_DIR) 2> /dev/null | true
	@mkdir $(STAGING_DIR)/unsigned 2> /dev/null | true

$(TEST_INSTALL_DIR):
	@mkdir $(TEST_INSTALL_DIR) 2> /dev/null | true

$(TLCONFIG): $(TLCONFIG_SRCS) $(STAGING_DIR)
	GOOS=darwin GOARCH=amd64 go build -o $(TLCONFIG) ./internal/cmd/tlconfig

$(CONFIG_BPF): $(CONFIG_BPF_SRCS) $(STAGING_DIR)
	GOOS=darwin GOARCH=amd64 go build -o $(CONFIG_BPF) ./internal/cmd/config-bpf

$(BIN_DIR)/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/darwin/amd64/tlserver \
		./$(TLSERVER_DIR)

$(BIN_DIR)/debug/darwin/amd64/tlserver: $(TLSERVER_SRCS)
	GOOS=darwin GOARCH=amd64 go build \
		-o $(BIN_DIR)/debug/darwin/amd64/tlserver \
		-tags debug \
		./$(TLSERVER_DIR)

$(EMBED_DIR)/tlsb_darwin_amd64.go: $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR) $(TLCONFIG) $(CONFIG_BPF)
	@cp $(BIN_DIR)/darwin/amd64/tlserver $(STAGING_DIR)
	@cp $(TLCONFIG) $(STAGING_DIR)
	@cp $(CONFIG_BPF) $(STAGING_DIR)
	$(call osxcodesign,$(STAGING_DIR)/tlserver)
	$(call osxcodesign,$(STAGING_DIR)/tlconfig)
	$(call osxcodesign,$(STAGING_DIR)/config-bpf)
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_darwin_amd64.go \
		-prefix $(STAGING_DIR) \
		-tags !debug \
		-ignore unsigned/* \
		$(STAGING_DIR)

$(EMBED_DIR)/tlsb_debug_darwin_amd64.go: $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR) $(TLCONFIG) $(CONFIG_BPF)
	@cp $(BIN_DIR)/debug/darwin/amd64/tlserver $(STAGING_DIR)
	@cp $(TLCONFIG) $(STAGING_DIR)
	@cp $(CONFIG_BPF) $(STAGING_DIR)
	go-bindata \
		-pkg tlserverbin \
		-o $(EMBED_DIR)/tlsb_debug_darwin_amd64.go \
		-prefix $(STAGING_DIR) \
		-tags debug \
		-ignore unsigned/* \
		$(STAGING_DIR)

# An alias for convenience.
debug: $(EMBED_DIR)/tlsb_debug_darwin_amd64.go

test:
	@go test -race -tags debug ./tlproc -args -elevated

clean:
	@rm -r $(STAGING_DIR) 2> /dev/null || true
