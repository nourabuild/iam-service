![Noura Auth](./noura-auth.png)


Noura Auth is an authentication microservice responsible for user identity, authentication, and token management across the Noura platform. The service provides a centralized mechanism for validating users and issuing access tokens that other services in the system can trust

The service is designed to operate in a microservices environment and expose authentication functionality through HTTP. Its primary responsibilities include user authentication, password validation, token generation, and identity verification

## Navigation

- **main.go** is the service entry point. It initializes dependencies and manages graceful shutdown
- **app** contains HTTP handlers and route registration
- **sdk** provides shared utilities and supporting tools
- **services** encapsulate external or internal service capabilities

## Getting Started

Run build make command with tests
```bash
make all
```

Build the application
```bash
make build
```

Run the application
```bash
make run
```
Create DB container
```bash
make docker-run
```

Shutdown DB Container
```bash
make docker-down
```

DB Integrations Test:
```bash
make itest
```

Live reload the application:
```bash
make watch
```

Run the test suite:
```bash
make test
```

Clean up binary from the last build:
```bash
make clean
```
