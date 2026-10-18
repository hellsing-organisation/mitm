BINARIES := mitmd mitmctl

.PHONY: build test vet clean bpf android demo

build:
	go build -buildvcs=false ./...

vet:
	go vet ./...

test:
	go test ./...

bpf:
	clang -target bpfel -O2 -g -Ibpf -c bpf/flows.bpf.c -o internal/bpf/flows.bpf.o
	go build -tags bpf -buildvcs=false ./...
	go test -tags bpf ./internal/bpf/

android: clean-dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -o dist/mitmd-linux-arm64 ./cmd/mitmd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -buildvcs=false -o dist/mitmctl-linux-arm64 ./cmd/mitmctl

clean-dist:
	rm -rf dist

demo:
	sudo bash scripts/demo.sh

clean: clean-dist
	go clean -testcache
