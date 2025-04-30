.PHONY: all
all: package-linux-amd64 package-darwin-amd64 package-darwin-arm64 package-windows

.PHONY: build
build: vendor
	go build -o kubectl-cilium .

.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o kubectl-cilium .

.PHONY: build-darwin-amd64
build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -o kubectl-cilium .

.PHONY: build-darwin-arm64
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o kubectl-cilium .

.PHONY: build-windows-amd64
build-windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o kubectl-cilium .

.PHONY: package-linux-amd64
package-linux-amd64: build-linux-amd64
	@tar -cvzf kubectl-cilium-linux-amd64.tar.gz kubectl-cilium
	@rm -rf kubectl-cilium
	sha256sum kubectl-cilium-linux-amd64.tar.gz

.PHONY: package-darwin-amd64
package-darwin-amd64: build-darwin-amd64
	@tar -cvzf kubectl-cilium-darwin-amd64.tar.gz kubectl-cilium
	@rm -rf kubectl-cilium
	sha256sum kubectl-cilium-darwin-amd64.tar.gz

.PHONY: package-darwin-arm64
package-darwin-arm64: build-darwin-arm64
	@tar -cvzf kubectl-cilium-darwin-arm64.tar.gz kubectl-cilium
	@rm -rf kubectl-cilium
	sha256sum kubectl-cilium-darwin-arm64.tar.gz

.PHONY: package-windows
package-windows: build-windows-amd64
	@tar -cvzf kubectl-cilium-windows-amd64.tar.gz kubectl-cilium
	@rm -rf kubectl-cilium
	sha256sum kubectl-cilium-windows-amd64.tar.gz

.PHONY: run
run: build
	./kubectl-cilium

.PHONY: lint
lint:
	golangci-lint run

.PHONY: clean
clean:
	rm -f kubectl-cilium
	rm -f kubectl-cilium-linux-amd64.tar.gz
	rm -f kubectl-cilium-darwin-amd64.tar.gz
	rm -f kubectl-cilium-darwin-arm64.tar.gz
	rm -f kubectl-cilium-windows-amd64.tar.gz

.PHONY: vendor
vendor:
	@go mod tidy
	@go mod vendor
	@go mod verify
