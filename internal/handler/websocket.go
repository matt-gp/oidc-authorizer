package handler

import (
	"context"
	"errors"
	"strings"

	"github.com/matt-gp/core/logger"

	"github.com/aws/aws-lambda-go/events"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var websocketEventTypeAttr = attribute.String("event.type", "websocket")

func (handler *Handler) HandleWebsocketEvent(ctx context.Context, event events.APIGatewayWebsocketProxyRequest) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	ctx, span := handler.tracer.Start(ctx, "websocket-event")
	defer span.End()

	span.SetAttributes(websocketEventTypeAttr)

	logger.Info(ctx, "handling event", websocketEventTypeAttr)
	logger.Debug(ctx, "received websocket event", websocketEventTypeAttr)

	token, err := handler.getTokenFromWebsocketEvent(event)
	if err != nil {
		logger.Error(ctx, "error getting token from event", websocketEventTypeAttr, attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, err
	}

	valid := handler.service.ValidateToken(ctx, token)
	logger.Debug(ctx, "token validation result", websocketEventTypeAttr, attribute.Bool("valid", valid))

	policyEffect := "Deny"
	if valid {
		policyEffect = "Allow"
	}

	resp := events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{
		PrincipalID: handler.service.GetPrincipalID(),
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
			"principalId": handler.service.GetPrincipalID(),
			"valid":       valid,
		},
	}

	logger.Info(ctx, "returning policy response", websocketEventTypeAttr)
	logger.Debug(ctx, "policy response created", websocketEventTypeAttr)

	span.SetAttributes(attribute.Bool("valid", valid))
	span.SetStatus(codes.Ok, "websocket event handled successfully")

	return resp, nil
}

func (handler *Handler) getTokenFromWebsocketEvent(event events.APIGatewayWebsocketProxyRequest) (string, error) {

	auth := event.Headers["Authorization"]
	if auth == "" {
		return "", errors.New("no token found in event")
	}

	if strings.Count(auth, " ") == 0 {
		return auth, nil
	}

	return strings.Split(auth, " ")[1], nil
}
