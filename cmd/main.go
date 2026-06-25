package main

import (
	"context"
	"fmt"
	"os"

	"github.com/matt-gp/core/logger"
	"github.com/matt-gp/core/otel"
	"github.com/matt-gp/oidc-authorizer/internal/handler"
	"github.com/matt-gp/oidc-authorizer/internal/service"

	"github.com/aws/aws-lambda-go/lambda"
	"go.opentelemetry.io/otel/attribute"
)

func main() {
	ctx := context.Background()

	provider, err := otel.NewProvider(ctx)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := provider.Shutdown(ctx); err != nil {
			fmt.Printf("Failed to shutdown provider: %v", err)
		}
	}()

	loggingProvider := provider.LoggerProvider.Logger("oidc-authorizer")
	meterProvider := provider.MeterProvider.Meter("oidc-authorizer")
	tracerProvider := provider.TracerProvider.Tracer("oidc-authorizer")

	// Initialize logger
	logger.SetProvider(loggingProvider)

	// Start the application
	logger.Info(ctx, "starting oidc-authorizer")

	acceptedIssuers := os.Getenv("ACCEPTED_ISSUERS")
	if acceptedIssuers == "" {
		logger.Error(ctx, "ACCEPTED_ISSUERS env var not set")
		os.Exit(1)
	}

	jwksURI := os.Getenv("JWKS_URI")
	if jwksURI == "" {
		logger.Error(ctx, "JWKS_URI env var not set")
		os.Exit(1)
	}

	principalIDClaims := os.Getenv("PRINCIPAL_ID_CLAIMS")
	if principalIDClaims == "" {
		principalIDClaims = "sub"
	}

	logger.Debug(ctx, "using principal_id_claims", attribute.String("principal_id_claims", principalIDClaims))

	s := service.New(tracerProvider, acceptedIssuers, jwksURI, principalIDClaims)
	h, err := handler.New(meterProvider, tracerProvider, s)
	if err != nil {
		logger.Error(ctx, err.Error())
		os.Exit(1)
	}

	lambda.Start(h.RouteEvent)

	logger.Info(ctx, "stopping oidc-authorizer")
}
