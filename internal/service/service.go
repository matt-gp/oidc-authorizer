package service

import (
	"context"

	"github.com/matt-gp/core/logger"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

var (
	eventStatusAttrSuccess = attribute.String("status", "success")
	eventStatusAttrError   = attribute.String("status", "error")
	errAttrKey             = "error"
)

type Service struct {
	AcceptedIssuers   string
	JwksUri           string
	PrincipalIDClaims string
	PrincipalID       string
	logger            log.Logger
	tracer            trace.Tracer
}

func New(logger log.Logger, tracer trace.Tracer, acceptedIssuers string, jwksuri string, principalIdClaims string) *Service {
	return &Service{
		AcceptedIssuers:   acceptedIssuers,
		JwksUri:           jwksuri,
		PrincipalIDClaims: principalIdClaims,
		logger:            logger,
		tracer:            tracer,
	}
}

func (s *Service) ValidateToken(ctx context.Context, token string) bool {

	ctx, span := s.tracer.Start(ctx, "validate-token")
	defer span.End()

	logger.Info(ctx, s.logger, "validating token")

	jwKeys, err := jwk.Fetch(ctx, s.JwksUri)
	if err != nil {
		logger.Error(ctx, s.logger, "failed to fetch JWKs", attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetAttributes(eventStatusAttrError)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	jwToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwKeys))
	if err != nil {
		logger.Error(ctx, s.logger, "failed to parse JWT", attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetAttributes(eventStatusAttrError)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	if err := jwt.Validate(jwToken, jwt.WithIssuer(s.AcceptedIssuers)); err != nil {
		logger.Error(ctx, s.logger, "failed to verify JWT", attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetAttributes(eventStatusAttrError)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	var principalID string
	if err := jwToken.Get(s.PrincipalIDClaims, &principalID); err != nil {
		logger.Error(ctx, s.logger, "failed to get principal ID claim", attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetAttributes(eventStatusAttrError)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	s.PrincipalID = principalID
	span.SetAttributes(eventStatusAttrSuccess)
	span.SetStatus(codes.Ok, "token validated successfully")

	return true
}

func (s *Service) GetPrincipalID() string {
	return s.PrincipalID
}
