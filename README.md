<p align="center">
	<img src="./noura-auth.png" alt="Noura Auth" width="420" />
</p>

Noura Auth is an authentication microservice responsible for user identity, authentication, and token management across the Noura platform. The service provides a centralized mechanism for validating users and issuing access tokens that other services in the system can trust.

The service operates in a microservices environment and exposes authentication functionality over HTTP. Its primary responsibilities are user authentication, password validation, token generation and rotation, and identity verification. User lifecycle changes are published to Kafka (`iam.user.created`, `iam.user.updated`) for downstream read models.

## Navigation

- **cmd/api/main.go** is the service entry point. It initializes dependencies, runs the background token-cleanup job, and manages graceful shutdown
- **internal/app** contains HTTP handlers and route registration
- **internal/sdk** provides shared utilities: middleware, models, database access, and SQL migrations
- **internal/services** encapsulates external service clients (JWT, Kafka, Mailtrap, Sentry, MinIO)

## Getting Started

1. Copy the environment template and fill in the required values (the JWT signing secret and database settings — see the comments in the file):

```bash
cp .env.example .env
```

Generate the signing secret rather than inventing or reusing one:

```bash
openssl rand -hex 32
```

2. Start PostgreSQL:

```bash
docker compose up -d
```

3. Run database migrations (requires [golang-migrate](https://github.com/golang-migrate/migrate)):

```bash
make migrate-up
```

4. Run the service:

```bash
make run
```

The API is served at `http://localhost:10067/api/v1`. Verify with:

```bash
curl http://localhost:10067/api/v1/health/readiness
```

Prometheus metrics are exposed at `http://localhost:10067/metrics`; restrict
this endpoint to your monitoring network in deployed environments.

## Development

Install the same golangci-lint version used by CI:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
```

Run the complete local verification gate. It checks module tidiness and
checksums, gofmt/goimports formatting, the build, static analysis, and unit
tests:

```bash
make verify
```

Project Go commands default to `-mod=readonly`, so an ignored local `vendor/`
directory cannot change dependency resolution. The dependency-maintenance
targets opt into module writes explicitly.

Run the unit tests, or the PostgreSQL integration suite (which requires
Docker and is selected explicitly with the `integration` build tag):

```bash
make test
make test-db
```

Run the same suite under the race detector, apply formatting, or generate a
handler coverage report:

```bash
make test-race
make fmt
make coverage
```

Run the configured idiomatic-Go linters independently:

```bash
make lint
```

Local Kafka for event publishing is optional. Leave `KAFKA_BROKERS` empty to
disable it; once brokers are configured, they must be reachable at startup:

```bash
make kafka
make kafka-ui   # browse topics at http://localhost:8081
```

## Migrations

```bash
make migrate-create   # create a new migration pair
make migrate-up       # apply pending migrations
make migrate-down     # roll back
make migrate-version  # show current version
```

Migrations live in `internal/sdk/migrate/sql` and are also applied automatically inside the `sqldb` test suite, so schema changes are exercised by CI.

## CI

GitHub Actions runs on pushes to `main`, pull requests, and manual dispatches.
It uses the same `make verify` gate with race detection enabled, runs database
tests separately through testcontainers, and scans dependencies with
govulncheck.

## Production safety

- Set `APP_ENV=production`. Startup then requires PostgreSQL certificate and
  hostname verification (`BLUEPRINT_DB_SSLMODE=verify-full`) and HTTPS for
  Mailtrap and password-reset URLs.
- Access-token lifetimes are capped at one hour and refresh-token lifetimes at
  90 days. The defaults remain 15 minutes and 30 days.
- Sentry events deliberately discard request bodies, cookies, sensitive
  headers, and client network data because IAM requests carry credentials.

## Architecture contracts

- Rate limiting is deliberately per-IP and in-process. Production deployments
  should enforce shared limits at the API gateway; do not turn the service
  limiter into a distributed subsystem.
- User lifecycle events use a transactional outbox and at-least-once Kafka
  delivery. Consumers must be idempotent. A crash after Kafka acknowledges an
  event but before the outbox row is marked can deliver that event again.
