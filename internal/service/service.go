package service

import (
	"context"
	"fmt"
	log "oidc-authorizer/internal/logger"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelLog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type Service struct {
	AcceptedIssuers       string
	JwksUri               string
	PrincipalIDClaims     string
	PrincipalID           string
	logger                otelLog.Logger
	meter                 metric.Meter
	tracer                trace.Tracer
	tokenValidatorCounter metric.Int64Counter
	tokenValidatorLatency metric.Float64Histogram
}

func New(logger otelLog.Logger, meter metric.Meter, tracer trace.Tracer, acceptedIssuers string, jwksuri string, principalIdClaims string) (*Service, error) {

	tokenValidatorCounter, err := meter.Int64Counter(
		"oidc_authorizer_token_validator_total",
		metric.WithDescription("Total number of token validation invocations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token validator counter: %w", err)
	}

	tokenValidatorLatency, err := meter.Float64Histogram(
		"oidc_authorizer_token_validator_latency",
		metric.WithDescription("Latency of token validation invocations"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token validator latency histogram: %w", err)
	}

	return &Service{
		AcceptedIssuers:       acceptedIssuers,
		JwksUri:               jwksuri,
		PrincipalIDClaims:     principalIdClaims,
		logger:                logger,
		meter:                 meter,
		tracer:                tracer,
		tokenValidatorCounter: tokenValidatorCounter,
		tokenValidatorLatency: tokenValidatorLatency,
	}, nil
}

func (s *Service) ValidateToken(ctx context.Context, token string) bool {

	start := time.Now()

	ctx, span := s.tracer.Start(ctx, "validate-token")
	defer span.End()

	log.Info(ctx, s.logger, "validating token")
	log.Debug(ctx, s.logger, "token", log.String("value", token))

	jwKeys, err := jwk.Fetch(ctx, s.JwksUri)
	if err != nil {

		log.Error(ctx, s.logger, "failed to fetch JWKs", log.Err(err))

		metricAttributes := []attribute.KeyValue{
			attribute.String("status", "error"),
			attribute.String("event.type", "jwk"),
		}

		s.tokenValidatorCounter.Add(ctx, 1, metric.WithAttributes(metricAttributes...))
		s.tokenValidatorLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(metricAttributes...))

		span.RecordError(err)
		span.SetAttributes(metricAttributes...)
		span.SetStatus(codes.Error, err.Error())

		return false
	}

	jwToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwKeys))
	if err != nil {
		log.Error(ctx, s.logger, "failed to parse JWT", log.Err(err))

		metricAttributes := []attribute.KeyValue{
			attribute.String("status", "error"),
			attribute.String("event.type", "parse"),
		}

		s.tokenValidatorCounter.Add(ctx, 1, metric.WithAttributes(metricAttributes...))
		s.tokenValidatorLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(metricAttributes...))

		span.RecordError(err)
		span.SetAttributes(metricAttributes...)
		span.SetStatus(codes.Error, err.Error())

		return false
	}

	if err := jwt.Validate(jwToken, jwt.WithIssuer(s.AcceptedIssuers)); err != nil {

		log.Error(ctx, s.logger, "failed to verify JWT", log.Err(err))

		metricAttributes := []attribute.KeyValue{
			attribute.String("status", "error"),
			attribute.String("event.type", "validate"),
		}

		s.tokenValidatorCounter.Add(ctx, 1, metric.WithAttributes(metricAttributes...))
		s.tokenValidatorLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(metricAttributes...))

		span.RecordError(err)
		span.SetAttributes(metricAttributes...)
		span.SetStatus(codes.Error, err.Error())

		return false
	}

	var principalID string
	if err := jwToken.Get(s.PrincipalIDClaims, &principalID); err != nil {

		log.Error(ctx, s.logger, "failed to get principal ID claim", log.Err(err))

		metricAttributes := []attribute.KeyValue{
			attribute.String("status", "error"),
			attribute.String("event.type", "claim"),
		}

		s.tokenValidatorCounter.Add(ctx, 1, metric.WithAttributes(metricAttributes...))
		s.tokenValidatorLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(metricAttributes...))

		span.RecordError(err)
		span.SetAttributes(metricAttributes...)
		span.SetStatus(codes.Error, err.Error())

		return false
	}

	s.PrincipalID = principalID

	metricAttributes := []attribute.KeyValue{
		attribute.String("status", "success"),
		attribute.String("event.type", "validate"),
	}

	s.tokenValidatorCounter.Add(ctx, 1, metric.WithAttributes(metricAttributes...))
	s.tokenValidatorLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(metricAttributes...))

	span.SetAttributes(metricAttributes...)
	span.SetStatus(codes.Ok, "token validated successfully")

	return true
}

func (s *Service) GetPrincipalID() string {
	return s.PrincipalID
}
