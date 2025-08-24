package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/matt-gp/oidc-authorizer/internal/handler"
	"github.com/matt-gp/oidc-authorizer/internal/logger"
	"github.com/matt-gp/oidc-authorizer/internal/otel"
	"github.com/matt-gp/oidc-authorizer/internal/service"

	"github.com/aws/aws-lambda-go/lambda"
	"go.opentelemetry.io/otel/codes"
)

func main() {
	ctx := context.Background()

	// Initialize OpenTelemetry provider
	provider, err := otel.NewProvider()
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := provider.Shutdown(ctx); err != nil {
			fmt.Printf("Failed to shutdown provider: %v", err)
		}
	}()

	l := provider.LoggerProvider.Logger("oidc-authorizer")
	m := provider.MeterProvider.Meter("oidc-authorizer")
	t := provider.TracerProvider.Tracer("oidc-authorizer")

	// Start tracing
	ctx, span := t.Start(ctx, "main")
	defer span.End()

	logger.Info(ctx, l, "starting oidc-authorizer")

	acceptedIssuers := os.Getenv("ACCEPTED_ISSUERS")
	if acceptedIssuers == "" {
		err := errors.New("ACCEPTED_ISSUERS env var not set")
		logger.Error(ctx, l, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	jwksURI := os.Getenv("JWKS_URI")
	if jwksURI == "" {
		err := errors.New("JWKS_URI env var not set")
		logger.Error(ctx, l, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	principalIDClaims := os.Getenv("PRINCIPAL_ID_CLAIMS")
	if principalIDClaims == "" {
		principalIDClaims = "sub"
		logger.Debug(ctx, l, "PRINCIPAL_ID_CLAIMS env var not set using default",
			logger.String("principal_id_claims", principalIDClaims))
	}

	s, err := service.New(l, m, t, acceptedIssuers, jwksURI, principalIDClaims)
	if err != nil {
		logger.Error(ctx, l, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	h, err := handler.New(l, m, t, s)
	if err != nil {
		logger.Error(ctx, l, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	lambda.Start(h.RouteEvent)

	logger.Info(ctx, l, "stopping oidc-authorizer")
}
