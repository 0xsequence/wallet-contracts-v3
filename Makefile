start-go:
	cd sdk-repo && $(go-server)

go-server:
	go run ./cmd/sequence/ server --debug --port 9999
