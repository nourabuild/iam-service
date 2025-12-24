# Project service

<img width="718" height="656" alt="image" src="https://github.com/user-attachments/assets/b2326c6e-354a-42d3-8987-40e4c77738bb" />

One Paragraph of project description goes here

## Goals

This repository template MUST provide a standardized foundation for microservices with:

- **CI/CD Ready** - Pre-configured pipelines for continuous integration and deployment
- **Observability** - Built-in metrics, logging, and tracing support
- **Production Features** - Health checks, graceful shutdown, and configuration management

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

## MakeFile

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
