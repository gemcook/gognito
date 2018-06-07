dep:
	dep ensure

test:
	go test ./...

lint:
	go vet ./...