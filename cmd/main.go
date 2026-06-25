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

	l := provider.LoggerProvider.Logger("oidc-authorizer")
	m := provider.MeterProvider.Meter("oidc-authorizer")
	t := provider.TracerProvider.Tracer("oidc-authorizer")

	logger.Info(ctx, l, "starting oidc-authorizer")

	acceptedIssuers := os.Getenv("ACCEPTED_ISSUERS")
	if acceptedIssuers == "" {
		logger.Error(ctx, l, "ACCEPTED_ISSUERS env var not set")
		os.Exit(1)
	}

	jwksURI := os.Getenv("JWKS_URI")
	if jwksURI == "" {
		logger.Error(ctx, l, "JWKS_URI env var not set")
		os.Exit(1)
	}

	principalIDClaims := os.Getenv("PRINCIPAL_ID_CLAIMS")
	if principalIDClaims == "" {
		principalIDClaims = "sub"
	}

	logger.Debug(ctx, l, "using principal_id_claims", attribute.String("principal_id_claims", principalIDClaims))

	s := service.New(l, t, acceptedIssuers, jwksURI, principalIDClaims)
	h, err := handler.New(l, m, t, s)
	if err != nil {
		logger.Error(ctx, l, err.Error())
		os.Exit(1)
	}

	lambda.Start(h.RouteEvent)

	logger.Info(ctx, l, "stopping oidc-authorizer")
}
