MODULE  := github.com/grvtyai/startrace/scanner-core
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

NEXUS_CMD     := ./cmd/startrace
SATELLITE_CMD := ./cmd/startrace-satellite
RADAR_CMD     := ./cmd/st-radar

BIN_DIR  := ./bin
DIST_DIR := ./dist

# ---------- dev build (current OS) ----------

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/startrace           $(NEXUS_CMD)
	go build $(LDFLAGS) -o $(BIN_DIR)/startrace-satellite $(SATELLITE_CMD)
	go build $(LDFLAGS) -o $(BIN_DIR)/st-radar            $(RADAR_CMD)

# ---------- release (cross-compile) ----------

.PHONY: release
release: nexus satellite

.PHONY: nexus
nexus:
	@mkdir -p $(DIST_DIR)
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o $(DIST_DIR)/startrace-linux-amd64          $(NEXUS_CMD)
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o $(DIST_DIR)/startrace-linux-arm64          $(NEXUS_CMD)
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o $(DIST_DIR)/startrace-windows-amd64.exe    $(NEXUS_CMD)
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o $(DIST_DIR)/startrace-darwin-amd64         $(NEXUS_CMD)
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o $(DIST_DIR)/startrace-darwin-arm64         $(NEXUS_CMD)

.PHONY: satellite
satellite:
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST_DIR)/startrace-satellite-linux-amd64   $(SATELLITE_CMD)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST_DIR)/startrace-satellite-linux-arm64   $(SATELLITE_CMD)

# ---------- util ----------

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
