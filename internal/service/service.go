package service

import (
	"context"
	"log/slog"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Service struct {
	AcceptedIssuers   string
	JwksUri           string
	PrincipalIDClaims string
	PrincipalID       string
}

func NewService(acceptedIssuers string, jwksuri string, principalIdClaims string) *Service {
	return &Service{
		AcceptedIssuers:   acceptedIssuers,
		JwksUri:           jwksuri,
		PrincipalIDClaims: principalIdClaims,
	}
}

func (s *Service) ValidateToken(ctx context.Context, token string) bool {

	slog.Info("validating token")
	slog.Debug("token", "value", token)

	jwKeys, err := jwk.Fetch(ctx, s.JwksUri)
	if err != nil {
		slog.Error("failed to fetch JWKs", "error", err)
		return false
	}

	jwToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwKeys))
	if err != nil {
		slog.Error("failed to parse JWT", "error", err)
		return false
	}

	if err := jwt.Validate(jwToken, jwt.WithIssuer(s.AcceptedIssuers)); err != nil {
		slog.Error("failed to verify JWT", "error", err)
		return false
	}

	var principalID string
	if err := jwToken.Get(s.PrincipalIDClaims, &principalID); err != nil {
		slog.Error("failed to get principal ID claim", "error", err)
		return false
	}

	s.PrincipalID = principalID

	return true
}

func (s *Service) GetPrincipalID() string {
	return s.PrincipalID
}
