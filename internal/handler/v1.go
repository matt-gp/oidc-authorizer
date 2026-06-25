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

var v1EventTypeAttr = attribute.String("event.type", "v1")

func (handler *Handler) HandleV1Event(ctx context.Context, event events.APIGatewayV2CustomAuthorizerV1Request) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	ctx, span := handler.tracer.Start(ctx, "v1-event")
	defer span.End()
	span.SetAttributes(v1EventTypeAttr)

	logger.Info(ctx, "handling event", v1EventTypeAttr)
	logger.Debug(ctx, "received event", v1EventTypeAttr)

	token, err := handler.getTokenFromV1Event(event)
	if err != nil {
		logger.Error(ctx, "error getting token from event", v1EventTypeAttr, attribute.String(errAttrKey, err.Error()))
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, err
	}

	valid := handler.service.ValidateToken(ctx, token)
	logger.Debug(ctx, "token validation result", v1EventTypeAttr, attribute.Bool("valid", valid))

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

	logger.Info(ctx, "returning policy response", v1EventTypeAttr)
	logger.Debug(ctx, "policy response created", v1EventTypeAttr)

	span.SetAttributes(attribute.Bool("valid", valid))
	span.SetStatus(codes.Ok, "event handled successfully")

	return resp, nil
}

func (handler *Handler) getTokenFromV1Event(event events.APIGatewayV2CustomAuthorizerV1Request) (string, error) {

	if event.IdentitySource == "" {
		return "", errors.New("no identity source found in event")
	}

	if strings.Count(event.IdentitySource, " ") == 0 {
		return event.IdentitySource, nil
	}

	return strings.Split(event.IdentitySource, " ")[1], nil
}
