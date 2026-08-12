.PHONY: fmt fmt-check lint test check

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -d . && exit 1)

lint:
	go vet ./...

test:
	go test ./...

check: fmt-check lint test
