# Variables
BINARY_NAME=dmh
CLI_BINARY_NAME=dmh-cli
CLI_DIR=cmd

# Build the main application and CLI tool
.PHONY: build
build: 
	go build -o $(BINARY_NAME) .
	cd $(CLI_DIR) && go build -o $(CLI_BINARY_NAME) .

# Clean up binaries
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
	rm -f $(CLI_DIR)/$(CLI_BINARY_NAME)

# Run tests
.PHONY: test
test:
	go test -cover ./...
	go test -cover -tags=integration .

# Format code
.PHONY: vet
vet:
	go fmt ./...
	go vet ./...

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build     - Build the main application and CLI tool"
	@echo "  clean     - Remove built binaries"
	@echo "  test      - Run tests"
	@echo "  vet       - Run vet and fmt"
	@echo "  help      - Show this help message"

