package main

import (
	"alai-shared/oidc-authorizer/internal/handler"
	"alai-shared/oidc-authorizer/internal/service"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	slog.Info("starting oidc-authorizer")

	configureLogger()

	acceptedIssuers := os.Getenv("ACCEPTED_ISSUERS")
	if acceptedIssuers == "" {
		slog.Error("ACCEPTED_ISSUERS env var not set")
		os.Exit(1)
	}

	jwksURI := os.Getenv("JWKS_URI")
	if jwksURI == "" {
		slog.Info("JWKS_URI env var not set")
		os.Exit(1)
	}

	principalIDClaims := os.Getenv("PRINCIPAL_ID_CLAIMS")
	if principalIDClaims == "" {
		principalIDClaims = "sub"
		slog.Debug("PRINCIPAL_ID_CLAIMS env var not set using default", "default", principalIDClaims)
	}

	s := service.NewService(acceptedIssuers, jwksURI, principalIDClaims)
	h := handler.NewHandler(s)
	lambda.Start(h.RouteEvent)

	slog.Info("stopping oidc-authorizer")
}

func configureLogger() {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
		slog.Debug("LOG_LEVEL env var not set using default", "default", logLevel)
	}

	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "fatal":
		level = slog.LevelError
	case "panic":
		level = slog.LevelError
	default:
		slog.Error("LOG_LEVEL env var not set to debug, info, warn, error, fatal or panic")
		os.Exit(1)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})))
	slog.Info("LOG_LEVEL env var set", "level", logLevel)
}
