package handler

import (
	"context"
	"errors"
	"strings"

	"github.com/matt-gp/oidc-authorizer/internal/logger"

	"github.com/aws/aws-lambda-go/events"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func (h *Handler) HandleV2Event(ctx context.Context, event events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	// Start tracing
	ctx, span := h.tracer.Start(ctx, "handle-event")
	defer span.End()

	logger.Info(ctx, h.logger, "handling event")
	logger.Debug(ctx, h.logger, "received v2 event")

	token, err := h.getTokenFromV2Event(ctx, event)
	if err != nil {
		logger.Error(ctx, h.logger, "error getting token from event", logger.Err(err))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, err
	}

	valid := h.s.ValidateToken(ctx, token)
	logger.Debug(ctx, h.logger, "token validation result", logger.Bool("valid", valid))

	policyEffect := "Deny"
	if valid {
		policyEffect = "Allow"
	}

	resp := events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{
		PrincipalID: h.s.GetPrincipalID(),
		PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Effect:   policyEffect,
					Action:   []string{"execute-api:Invoke"},
					Resource: []string{"*"},
				},
			},
		},
		Context: map[string]interface{}{
			"principalId": h.s.GetPrincipalID(),
			"valid":       valid,
		},
	}

	logger.Info(ctx, h.logger, "returning policy response")
	logger.Debug(ctx, h.logger, "policy response created")

	span.SetAttributes(attribute.Bool("valid", valid))
	span.SetStatus(codes.Ok, "v2 event handled successfully")

	return resp, nil
}

func (h *Handler) getTokenFromV2Event(ctx context.Context, event events.APIGatewayV2CustomAuthorizerV2Request) (string, error) {

	_, span := h.tracer.Start(ctx, "get-token")
	defer span.End()

	span.SetAttributes(attribute.String("event.type", "v2"))

	if len(event.IdentitySource) == 0 {
		err := errors.New("no identity source found in event")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	span.SetStatus(codes.Ok, "identity source found")

	if strings.Count(event.IdentitySource[0], " ") == 0 {
		return event.IdentitySource[0], nil
	}

	return strings.Split(event.IdentitySource[0], " ")[1], nil
}
