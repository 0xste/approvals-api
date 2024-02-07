BUILDDIR=./build
GOCMD=go
GOBUILD=GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOCMD) build
GOTEST=$(GOCMD) test
GOTESTFLAGS=-cover -race
BINARY_PREFIX=approvals-api-

# Discover programs in ./cmd.
PROGRAM_DIRS := ${shell find cmd -mindepth 1 -maxdepth 1 -type d -print}
# Generate target in ./build for each program in ./cmd.
TARGETS := $(addprefix $(BUILDDIR)/, $(addprefix $(BINARY_PREFIX), $(notdir $(PROGRAM_DIRS))))

# Go programs are always out of date.
.PHONY: all $(TARGETS) clean test dep update-tools gen-proto gen-gateway gen-openapi gen-mocks gen-all lint cuke local-db-up product-api-local

# The normal $GOFLAGS are pulled in automatically by the Go tool.
# However they don't support arguments with spaces or quoted strings yet.
# Therefore we add $GOFLAGS2 to pass the arguments directly to the command.
# https://github.com/golang/go/issues/26849
GOFLAGS2=-gcflags 'all=-N -l'

# By default, just build the Go binaries.
all: build

# Build all Go binaries.
build: $(TARGETS)

# Remove Go binaries.
.PHONY:
clean:
	rm -rvf $(BUILDDIR)

# Individual build invocations.
$(TARGETS): %: dep
	@ mkdir -p ./cmd/$(subst $(BINARY_PREFIX),,$(notdir $@))/build
	$(GOBUILD) $(GOFLAGS2) -o ./cmd/$(subst $(BINARY_PREFIX),,$(notdir $@))/build/$(subst $(BINARY_PREFIX),,$(notdir $@)) ./cmd/$(subst $(BINARY_PREFIX),,$(notdir $@))

.PHONY: lint
lint:
	golangci-lint run --out-format colored-line-number --new-from-rev origin/main

# Run unit tests.
.PHONY: test
test: dep
	$(GOTEST) $(GOTESTFLAGS) ./...

.PHONY: dep
	go mod download

## Protobuf related paths
PROTO_GEN_PATH = ./proto/gen/
PROTO_SPEC_PATH = ./proto ./proto/models/*.proto ./proto/*.proto
PROTO_OPENAPI_PATH = ./openapi

## Generate protobuf files
.PHONY: gen-proto
gen-proto:
	protoc --proto_path ${PROTO_SPEC_PATH} \
	--go_out=${PROTO_GEN_PATH} --go_opt paths=import \
	--go-grpc_out ${PROTO_GEN_PATH} --go-grpc_opt paths=source_relative \

## Generate grpc audit files
.PHONY: gen-gateway
gen-gateway:
	protoc --proto_path ${PROTO_SPEC_PATH} \
		--grpc-gateway_out ${PROTO_GEN_PATH} \
        --grpc-gateway_opt logtostderr=true \
        --grpc-gateway_opt paths=import \
        --grpc-gateway_opt generate_unbound_methods=true

.PHONY: gen-openapi
gen-openapi:
	go install ./pkg/protoc-gen-openapi
	protoc --proto_path ./proto ./proto/approvals.proto \
		-I. \
        --openapi_out=./docs/openapi/approvals \
		--openapi_opt title="Approvals API"

.PHONY: gen-mocks
gen-mocks:
	mockery

.PHONY: gen-all
gen-all: gen-proto gen-gateway gen-openapi gen-mocks
