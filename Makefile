# ==============================================================================
# Load environment variables 
ifneq (,$(wildcard ./.env))
include .env
export
endif

.PHONY: run tidy deps-list deps-upgrade deps-cleancache verify-checksums list \
	lint staticcheck migrate-create migrate-up migrate-down migrate-force \
	migrate-version migrate-drop test test-race coverage kafka kafka-ui \
	kafka-topics kafka-topics-list

# ==============================================================================
# Main

run:
	go run ./cmd/api/main.go

# ==============================================================================
# Modules support

tidy:
	go mod tidy

deps-list:
	go list -m -u -mod=readonly all

deps-upgrade:
	go get -u -v ./...
	go mod tidy

deps-cleancache:
	go clean -modcache

verify-checksums:
	go mod verify

list:
	go list -mod=mod all

lint:
	CGO_ENABLED=0 go vet ./...
	go tool staticcheck -checks=all ./...

staticcheck:
	go tool staticcheck -checks=all ./...

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

coverage:
	go test -coverprofile=coverage.out ./internal/app/...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report written to coverage.html"


# Kafka
kafka:
	docker run -d --name kafka -p 9092:9092 apache/kafka:4.2.0

kafka-ui:
	docker run -d --name kafka-ui \
  -p 8081:8080 \
  --link kafka:kafka \
  -e KAFKA_CLUSTERS_0_NAME=local \
  -e KAFKA_CLUSTERS_0_BOOTSTRAPSERVERS=kafka:9092 \
  provectuslabs/kafka-ui:latest

kafka-topics:
	docker exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic iam.user.created --partitions 1 --replication-factor 1
	docker exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic iam.user.updated --partitions 1 --replication-factor 1

kafka-topics-list:
	docker exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --list
