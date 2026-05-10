# ==============================================================================
# Load environment variables 
ifneq (,$(wildcard ./.env))
include .env
export
endif

# ==============================================================================
# Define dependencies
GOLANG          := golang:1.26
ALPINE          := alpine:3.22

POSTGRES        := postgres:17.2
SERVICE_APP    	:= iam-service
BASE_IMAGE_NAME := insidious000
VERSION         := 0.0.1
API_IMAGE       := $(BASE_IMAGE_NAME)/$(SERVICE_APP):$(VERSION)

# ==============================================================================
# Main

run:
	lsof -i :10067 | awk 'NR!=1 {print $$2}' | xargs -r kill -9
	go run ./cmd/api/main.go

# ==============================================================================
# Modules support

deps-reset:
	git checkout -- go.mod
	go mod tidy
	go mod vendor

tidy:
	go mod tidy
	go mod vendor

deps-list:
	go list -m -u -mod=readonly all

deps-upgrade:
	go get -u -v ./...
	go mod tidy
	go mod vendor

deps-cleancache:
	go clean -modcache

verify-checksums:
	go mod verify

list:
	go list -mod=mod all

lint:
	CGO_ENABLED=0 go vet ./...
	staticcheck -checks=all ./...

staticcheck:
	staticcheck -checks=all ./...

# ==============================================================================
# Database migrations

# Create empty migration manually
migrate-create:
	@read -p "Enter migration name: " name; \
	migrate create -ext sql -dir internal/sdk/migrate/sql -seq $$name

# Run migrations
migrate-up:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)?sslmode=disable" up

migrate-down:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)?sslmode=disable" down

migrate-force:
	@read -p "Enter version: " version; \
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)?sslmode=disable" force $$version

migrate-version:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)?sslmode=disable" version

migrate-drop:
	migrate -path internal/sdk/migrate/sql -database "$(DATABASE_URL)?sslmode=disable" drop -f


# ==============================================================================

# go version -m $(which staticcheck) | head -n 1 | awk '{print $NF}'

revert:
	git reset --hard HEAD~1

test:
	go test -coverprofile=coverage.out ./internal/app/... && go tool cover -html=coverage.out -o coverage.html
	open coverage.html


# Kafka 4.0
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


# docker ps
# docker exec <container_name> createdb -U postgres noura_iam_service_db