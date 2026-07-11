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

func SetupSentry(ctx context.Context, cfg config.Sentry, logger *slog.Logger) (func(context.Context) error, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.DSN == "" {
		logger.InfoContext(ctx, "sentry disabled", "reason", "SENTRY_DSN is not configured")
		return func(context.Context) error { return nil }, nil
	}

	if err := githubsentry.Init(githubsentry.ClientOptions{
		Dsn:              cfg.DSN,
		Environment:      cfg.Environment,
		Release:          cfg.Release,
		AttachStacktrace: true,
		EnableTracing:    cfg.SentryTracesSampleRate > 0,
		TracesSampleRate: cfg.SentryTracesSampleRate,
		BeforeSend: func(event *githubsentry.Event, hint *githubsentry.EventHint) *githubsentry.Event {
			return scrubSentryRequest(event)
		},
		BeforeSendTransaction: func(event *githubsentry.Event, hint *githubsentry.EventHint) *githubsentry.Event {
			return scrubSentryRequest(event)
		},
	}); err != nil {
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

func scrubSentryRequest(event *githubsentry.Event) *githubsentry.Event {
	if event == nil || event.Request == nil || event.Request.QueryString == "" {
		return event
	}
	query, err := url.ParseQuery(event.Request.QueryString)
	if err != nil {
		// A malformed query cannot be safely inspected for bearer values.
		event.Request.QueryString = "[Filtered]"
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
		event.Request.QueryString = query.Encode()
	}
	return event
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
