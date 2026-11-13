BIN := bin
.PHONY: all test install
all:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o $(BIN)/sydguard-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(BIN)/sydguard-linux-amd64 .
	go build -trimpath -o $(BIN)/sydguard .
test:
	go vet ./... && go test ./...
install: all
	mkdir -p $(HOME)/.local/bin
	cp $(BIN)/sydguard $(BIN)/sydguard-linux-* $(HOME)/.local/bin/
