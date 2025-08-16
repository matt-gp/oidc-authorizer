package main

import (
	"context"
	"errors"
	"fmt"
	"oidc-authorizer/internal/handler"
	log "oidc-authorizer/internal/logger"
	"oidc-authorizer/internal/otel"
	"oidc-authorizer/internal/service"
	"os"

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

	logger := provider.LoggerProvider.Logger("oidc-authorizer")
	meter := provider.MeterProvider.Meter("oidc-authorizer")
	tracer := provider.TracerProvider.Tracer("oidc-authorizer")

	// Start tracing
	ctx, span := tracer.Start(ctx, "main")
	defer span.End()

	log.Info(ctx, logger, "starting oidc-authorizer")

	acceptedIssuers := os.Getenv("ACCEPTED_ISSUERS")
	if acceptedIssuers == "" {
		err := errors.New("ACCEPTED_ISSUERS env var not set")
		log.Error(ctx, logger, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	jwksURI := os.Getenv("JWKS_URI")
	if jwksURI == "" {
		err := errors.New("JWKS_URI env var not set")
		log.Error(ctx, logger, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	principalIDClaims := os.Getenv("PRINCIPAL_ID_CLAIMS")
	if principalIDClaims == "" {
		principalIDClaims = "sub"
		log.Debug(ctx, logger, "PRINCIPAL_ID_CLAIMS env var not set using default",
			log.String("principal_id_claims", principalIDClaims))
	}

	s, err := service.New(logger, meter, tracer, acceptedIssuers, jwksURI, principalIDClaims)
	if err != nil {
		log.Error(ctx, logger, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	h, err := handler.New(logger, meter, tracer, s)
	if err != nil {
		log.Error(ctx, logger, err.Error())
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		os.Exit(1)
	}

	lambda.Start(h.RouteEvent)

	log.Info(ctx, logger, "stopping oidc-authorizer")
}
