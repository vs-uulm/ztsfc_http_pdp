.PHONY: source
source:
	go mod tidy
	go build -v ./cmd/ztsfc_http_pdp/main.go
