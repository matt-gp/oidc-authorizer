package service

import (
	"context"

	"github.com/matt-gp/core/logger"
	"github.com/matt-gp/oidc-authorizer/internal/handler"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	tracer            trace.Tracer
}

// Ensure that the Service struct implements the handler.Service interface.
var _ handler.Service = (*Service)(nil)

// New creates a new Service with the provided tracer, accepted issuers, JWKS URI, and principal ID claims.
func New(tracer trace.Tracer, acceptedIssuers string, jwksuri string, principalIdClaims string) *Service {
	return &Service{
		AcceptedIssuers:   acceptedIssuers,
		JwksUri:           jwksuri,
		PrincipalIDClaims: principalIdClaims,
		tracer:            tracer,
	}
}

// ValidateToken validates the provided token against the accepted issuers and JWKS URI.
// It returns true if the token is valid, false otherwise.
func (s *Service) ValidateToken(ctx context.Context, token string) bool {

	ctx, span := s.tracer.Start(ctx, "validate-token")
	defer span.End()

	logger.Info(ctx, "validating token")

	jwKeys, err := jwk.Fetch(ctx, s.JwksUri)
	if err != nil {
		logger.Error(ctx, "failed to fetch JWKs", attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetAttributes(eventStatusAttrError)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	jwToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwKeys))
	if err != nil {
		logger.Error(ctx, "failed to parse JWT", attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetAttributes(eventStatusAttrError)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	if err := jwt.Validate(jwToken, jwt.WithIssuer(s.AcceptedIssuers)); err != nil {
		logger.Error(ctx, "failed to verify JWT", attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetAttributes(eventStatusAttrError)
		span.SetStatus(codes.Error, err.Error())
		return false
	}

	var principalID string
	if err := jwToken.Get(s.PrincipalIDClaims, &principalID); err != nil {
		logger.Error(ctx, "failed to get principal ID claim", attribute.String(errAttrKey, err.Error()))
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

// GetPrincipalID returns the principal ID extracted from the validated token.
func (s *Service) GetPrincipalID() string {
	return s.PrincipalID
}
