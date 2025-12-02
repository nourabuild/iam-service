
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
