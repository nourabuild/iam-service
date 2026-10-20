# ==============================================================================
# Load environment variables
ifneq (,$(wildcard ./.env))
include .env
export
endif

# Ignore the local (gitignored) vendor/ dir and never rewrite go.mod implicitly.
export GOFLAGS = -mod=readonly

UNIT_TEST_PACKAGES := \
	./cmd/... \
	./internal/app/... \
	./internal/sdk/config/... \
	./internal/sdk/errs/... \
	./internal/sdk/middleware/... \
	./internal/sdk/models/... \
	./internal/sdk/observability/... \
	./internal/services/...

.PHONY: run build fmt fmt-check tidy tidy-check deps-list deps-upgrade \
	deps-cleancache verify-checksums module-check list lint staticcheck verify \
	migrate-create migrate-up migrate-down migrate-force migrate-version \
	migrate-drop test test-race test-unit test-db coverage kafka kafka-ui \
	kafka-topics kafka-topics-list

# ==============================================================================
# Main

run:
	go run ./cmd/api

build:
	CGO_ENABLED=0 go build ./...

# ==============================================================================
# Modules support

tidy:
	GOFLAGS=-mod=mod go mod tidy

tidy-check:
	go mod tidy -diff

deps-list:
	go list -m -u all

deps-upgrade:
	GOFLAGS=-mod=mod go get -u -v ./...
	GOFLAGS=-mod=mod go mod tidy

deps-cleancache:
	go clean -modcache

verify-checksums:
	go mod verify

module-check: verify-checksums tidy-check

list:
	go list all

# ==============================================================================
# Formatting and static analysis

fmt:
	golangci-lint fmt

# Treat formatter output as a failure even on formatter paths that exit zero
# after printing a diff, while preserving real formatter errors.
fmt-check:
	@output="$$(golangci-lint fmt --diff)"; status=$$?; \
	if [ -n "$$output" ]; then \
		printf '%s\n' "$$output"; \
	fi; \
	if [ $$status -ne 0 ] || [ -n "$$output" ]; then exit 1; fi

lint:
	golangci-lint run

staticcheck:
	go tool staticcheck -checks=all ./...

# Keep this target as the single developer and CI entry point. Database tests
# remain separate because they require Docker through testcontainers.
verify: module-check fmt-check build lint test-unit

# ==============================================================================
# Database migrations

# Create empty migration manually
migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir internal/sdk/migrate/sql -seq $$name

# Run migrations
migrate-up:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)" down

migrate-force:
	@read -p "Enter version: " version; \
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)" force $$version

migrate-version:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)" version

migrate-drop:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)" drop -f


# ==============================================================================

# go version -m $(which staticcheck) | head -n 1 | awk '{print $NF}'

test:
	go test ./...

test-race:
	go test -race ./...

test-unit:
	go test $(UNIT_TEST_PACKAGES)

test-db:
	go test -tags=integration ./internal/sdk/sqldb/...

coverage:
	go test -coverprofile=coverage.out ./internal/app/...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report written to coverage.html"


# Kafka
kafka:
	docker run -d --name kafka -p 9092:9092 apache/kafka:4.2.0

# kafka-ui joins kafka's Docker network and talks to its INTERNAL listener.
# Port 8090 avoids clashing with Expo/Metro, which uses 8081.

kafka-ui:
	docker run -d --name kafka-ui \
  -p 8090:8080 \
  --network brgts_default \
  -e KAFKA_CLUSTERS_0_NAME=local \
  -e KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS=kafka:29092 \
  provectuslabs/kafka-ui:latest

kafka-topics:
	docker exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic iam.user.created --partitions 1 --replication-factor 1
	docker exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic iam.user.updated --partitions 1 --replication-factor 1

kafka-topics-list:
	docker exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --list
