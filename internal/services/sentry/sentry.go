// Package sentry configures error reporting and Gin request integration.
package sentry

import (
	"context"
	"log/slog"
	"net/url"

	githubsentry "github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/middleware"
)

var requestHeaderFilter = newSentryDataCollection()

func newSentryDataCollection() *githubsentry.DataCollection {
	return &githubsentry.DataCollection{
		UserInfo: githubsentry.Set(false),
		Cookies: &githubsentry.KeyValueCollectionBehavior{
			Mode: githubsentry.CollectionOff,
		},
		HTTPHeaders: &githubsentry.HeaderCollectionConfig{
			Request: &githubsentry.KeyValueCollectionBehavior{
				Mode: githubsentry.CollectionDenyList,
				Terms: []string{
					"cookie",
					"forwarded",
					"-ip",
					"remote-",
					"via",
					"-user",
				},
			},
		},
		HTTPBodies: []githubsentry.BodyType{},
		QueryParams: &githubsentry.KeyValueCollectionBehavior{
			Mode:  githubsentry.CollectionDenyList,
			Terms: []string{"code"},
		},
	}
}

func SetupSentry(ctx context.Context, cfg config.Sentry, logger *slog.Logger) (func(context.Context) error, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DSN == "" {
		logger.InfoContext(ctx, "sentry disabled", "reason", "SENTRY_DSN is not configured")
		return func(context.Context) error { return nil }, nil
	}

	if err := githubsentry.Init(clientOptions(cfg)); err != nil {
		return nil, err
	}

	logger.InfoContext(ctx, "sentry enabled", "environment", cfg.Environment)
	return func(ctx context.Context) error {
		if ok := githubsentry.FlushWithContext(ctx); !ok {
			return context.DeadlineExceeded
		}
		return nil
	}, nil
}

func clientOptions(cfg config.Sentry) githubsentry.ClientOptions {
	return githubsentry.ClientOptions{
		Dsn:              cfg.DSN,
		Environment:      cfg.Environment,
		Release:          cfg.Release,
		AttachStacktrace: true,
		DataCollection:   newSentryDataCollection(),
		EnableTracing:    cfg.SentryTracesSampleRate > 0,
		TracesSampleRate: cfg.SentryTracesSampleRate,
		BeforeSend: func(event *githubsentry.Event, _ *githubsentry.EventHint) *githubsentry.Event {
			return scrubSentryRequest(event)
		},
		BeforeSendTransaction: func(event *githubsentry.Event, _ *githubsentry.EventHint) *githubsentry.Event {
			return scrubSentryRequest(event)
		},
	}
}

func scrubSentryRequest(event *githubsentry.Event) *githubsentry.Event {
	if event == nil || event.Request == nil {
		return event
	}

	request := event.Request

	// IAM request bodies contain passwords and bearer/reset tokens. The Sentry
	// HTTP integrations can buffer and attach small request bodies, so always
	// remove them before both error and transaction events leave the process.
	request.Data = ""
	request.Cookies = ""
	request.Env = nil
	removeSensitiveHeaders(request.Headers)

	if request.QueryString == "" {
		return event
	}

	query, err := url.ParseQuery(request.QueryString)
	if err != nil {
		// A malformed query cannot be safely inspected for bearer values.
		request.QueryString = "[Filtered]"
		return event
	}
	changed := false
	for _, key := range []string{"access_token", "refresh_token", "token", "code"} {
		if query.Has(key) {
			query.Set(key, "[Filtered]")
			changed = true
		}
	}
	if changed {
		request.QueryString = query.Encode()
	}
	return event
}

func removeSensitiveHeaders(headers map[string]string) {
	if len(headers) == 0 {
		return
	}

	// sentry-go v0.48 replaced IsSensitiveHeader with DataCollection filters.
	// Filter probe values so sensitive keys can still be removed rather than
	// retained with redacted values.
	const probeValue = "iam-service-header-probe"
	probes := make(map[string]string, len(headers))
	for key := range headers {
		probes[key] = probeValue
	}
	filtered := requestHeaderFilter.FilterRequestHeaders(probes)
	for key := range probes {
		if filtered[key] != probeValue {
			delete(headers, key)
		}
	}
}

func CaptureException(ctx context.Context, err error, level githubsentry.Level, tags map[string]string) {
	if err == nil {
		return
	}

	hub := githubsentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = githubsentry.CurrentHub()
	}

	hub.WithScope(func(scope *githubsentry.Scope) {
		scope.SetLevel(level)
		if len(tags) > 0 {
			scope.SetTags(tags)
		}
		if client := hub.Client(); client != nil {
			client.CaptureException(err, &githubsentry.EventHint{
				Context:           ctx,
				OriginalException: err,
			}, scope)
		}
	})
}

func LevelFromSlog(level slog.Level) githubsentry.Level {
	switch {
	case level >= slog.LevelError:
		return githubsentry.LevelError
	case level >= slog.LevelWarn:
		return githubsentry.LevelWarning
	case level <= slog.LevelDebug:
		return githubsentry.LevelDebug
	default:
		return githubsentry.LevelInfo
	}
}

func SentryMiddleware(cfg config.Sentry) gin.HandlerFunc {
	return sentrygin.New(sentrygin.Options{
		Repanic:         true,
		WaitForDelivery: false,
		Timeout:         cfg.SentryFlushTimeout,
	})
}

func SentryRequestContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		if hub := sentrygin.GetHubFromContext(c); hub != nil {
			hub.ConfigureScope(func(scope *githubsentry.Scope) {
				if requestID := c.GetString("request_id"); requestID != "" {
					scope.SetTag("request_id", requestID)
				}
				if route := c.FullPath(); route != "" {
					scope.SetTag("route", route)
				}
			})
		}
		c.Next()
	}
}

func SentryPrincipal() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, err := middleware.Principal(c)
		if err == nil {
			if hub := sentrygin.GetHubFromContext(c); hub != nil {
				hub.ConfigureScope(func(scope *githubsentry.Scope) {
					scope.SetUser(githubsentry.User{ID: principal.ID})
					if principal.IsAdmin() {
						scope.SetTag("role", "admin")
					} else {
						scope.SetTag("role", "user")
					}
				})
			}
		}
		c.Next()
	}
}
