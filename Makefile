BIN := bin
GO_BUILD := go build -trimpath
.PHONY: all ui test check install

all: ui
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO_BUILD) -o $(BIN)/sydguard-linux-arm64 ./cmd/sydguard
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO_BUILD) -o $(BIN)/sydguard-linux-amd64 ./cmd/sydguard
	$(GO_BUILD) -o $(BIN)/sydguard ./cmd/sydguard

ui:
	cd web && bun install --frozen-lockfile >/dev/null && bun run build

test:
	go test ./... && cd web && bun run test

check:
	scripts/check.sh

# Installs the Mac binary plus the Linux binaries it copies into Lima VMs.
install: all
	mkdir -p $(HOME)/.local/bin
	cp $(BIN)/sydguard $(BIN)/sydguard-linux-* $(HOME)/.local/bin/
