package observability

import (
	"context"
	"log/slog"
	"net/url"
	"strings"

	"github.com/nourabuild/iam-service/internal/sdk/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func SetupTracing(ctx context.Context, cfg config.Observability, logger *slog.Logger) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	if cfg.OTLPHTTPEndpoint == "" {
		logger.InfoContext(ctx, "otel exporter disabled")
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := otlptracehttp.New(ctx, otlpHTTPOptions(cfg.OTLPHTTPEndpoint)...)
	if err != nil {
		return nil, err
	}

	res, err := resource.New(ctx, resource.WithAttributes(attribute.String("service.name", cfg.ServiceName)))
	if err != nil {
		return nil, err
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(provider)

	return provider.Shutdown, nil
}

func otlpHTTPOptions(endpoint string) []otlptracehttp.Option {
	endpoint = strings.TrimSpace(endpoint)

	u, err := url.Parse(endpoint)
	if err == nil && u.Scheme != "" && u.Host != "" {
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(u.Host)}
		if u.Path != "" && u.Path != "/" {
			opts = append(opts, otlptracehttp.WithURLPath(u.Path))
		}
		if u.Scheme == "http" {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return opts
	}

	return []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
}
