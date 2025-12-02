# ==============================================================================
# Load environment variables 
ifneq (,$(wildcard ./.env))
include .env
export
endif

# ==============================================================================
# Define dependencies
GOLANG          := golang:1.25
ALPINE          := alpine:3.22

POSTGRES        := postgres:17.2
SERVICE_APP    	:= iam-service
BASE_IMAGE_NAME := insidious000
VERSION         := 0.0.1
API_IMAGE       := $(BASE_IMAGE_NAME)/$(SERVICE_APP):$(VERSION)

# ==============================================================================
# Main

run:
	lsof -i :8080 | awk 'NR!=1 {print $$2}' | xargs -r kill -9
	go run ./cmd/meetx/main.go

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