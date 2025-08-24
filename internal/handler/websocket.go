package handler

import (
	"context"
	"errors"
	log "oidc-authorizer/internal/logger"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

func (h *Handler) HandleWebsocketEvent(ctx context.Context, event events.APIGatewayWebsocketProxyRequest) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	ctx, span := h.tracer.Start(ctx, "handle-event")
	defer span.End()

	log.Info(ctx, h.logger, "handling event")
	log.Debug(ctx, h.logger, "received websocket event")

	token, err := h.getTokenFromWebsocketEvent(ctx, event)
	if err != nil {
		log.Error(ctx, h.logger, "error getting token from event", log.Err(err))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, err
	}

	valid := h.s.ValidateToken(ctx, token)
	log.Debug(ctx, h.logger, "token validation result", log.Bool("valid", valid))

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

	log.Info(ctx, h.logger, "returning policy response")
	log.Debug(ctx, h.logger, "policy response created")

	span.SetAttributes(attribute.Bool("valid", valid))
	span.SetStatus(codes.Ok, "websocket event handled successfully")

	return resp, nil
}

func (h *Handler) getTokenFromWebsocketEvent(ctx context.Context, event events.APIGatewayWebsocketProxyRequest) (string, error) {

	_, span := h.tracer.Start(ctx, "get-token")
	defer span.End()

	span.SetAttributes(attribute.String("event.type", "websocket"))

	if event.Headers["Authorization"] != "" {
		span.SetStatus(codes.Ok, "token found in event")
		return strings.Split(event.Headers["Authorization"], " ")[1], nil
	}

	err := errors.New("no token found in event")
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())

	return "", err
}
