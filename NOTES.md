
## Current contracts (intentional, revisit before production)

- **Rate limiting** is enforced per-IP in-process (`internal/app/routes.go`) as
  basic protection only. The target architecture enforces limits centrally at
  the API gateway across all services. Do not grow the in-process limiter into
  a Redis-backed/distributed one.
- **Event delivery is at-least-once via a transactional outbox.** User
  lifecycle events are written to `auth.outbox` in the same transaction as
  the user mutation, then drained to Kafka in commit order by a relay loop
  (`internal/app/outbox_relay.go`). Events survive Kafka outages and service
  restarts; a crash between produce and mark re-sends, so **consumers must be
  idempotent** (events carry `user_id` + `occurred_at`). If Kafka is down at
  startup the relay does not run and events accumulate until the service
  restarts with Kafka reachable. Delivered events are kept 7 days for
  debugging, then reaped by the cleanup job.

## Roadmap

Features to integrate later as needed.

### Observability
- **Prometheus** — Metrics collection  
  https://prometheus.io
- **Grafana Loki** — Log aggregation  
  https://grafana.com/oss/loki
- **Sentry** — Error tracking and tracing  
  https://sentry.io

### Security
- **Keycloak** — Identity provider (e.g., "Sign in with Noura")  
  https://www.keycloak.org
- **Rate Limiting** — API Gateway level (Kong, AWS API Gateway, or Traefik)
- **WebAuthn** — Passkey support  
  https://github.com/go-webauthn/webauthn
- **JWT Authentication** — Stateless auth tokens

### Database
- **Database Migrations** — TBD
- **Redis** — Caching layer

### API
- **OpenAPI Documentation** — Useful for docs sites (Docusaurus, Mintlify) and AI agent SDKs
- **API Versioning** — Version management strategy

### Infrastructure
- **Kubernetes Manifests** — Deployment configurations
- **Helm Charts** — Package management for K8s
- **Terraform Modules** — Infrastructure as code
- **Health Checks** — Liveness and readiness probes

### Developer Experience
- **Pre-commit Hooks** — Automated checks before commits
- **Linting** — Code quality with golangci-lint
- **Conventional Commits** — Standardized commit messages
