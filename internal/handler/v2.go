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

var v2EventTypeAttr = attribute.String("event.type", "v2")

func (handler *Handler) HandleV2Event(ctx context.Context, event events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	ctx, span := handler.tracer.Start(ctx, "v2-event")
	defer span.End()

	span.SetAttributes(v2EventTypeAttr)

	logger.Info(ctx, "handling event", v2EventTypeAttr)
	logger.Debug(ctx, "received event", v2EventTypeAttr)

	token, err := handler.getTokenFromV2Event(event)
	if err != nil {
		logger.Error(ctx, "error getting token from event", v2EventTypeAttr, attribute.String(errAttrKey, err.Error()))
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, err
	}

	valid := handler.service.ValidateToken(ctx, token)
	logger.Debug(ctx, "token validation result", v2EventTypeAttr, attribute.Bool("valid", valid))

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

	logger.Info(ctx, "returning policy response", v2EventTypeAttr)
	logger.Debug(ctx, "policy response created", v2EventTypeAttr)

	span.SetAttributes(attribute.Bool("valid", valid))
	span.SetStatus(codes.Ok, "v2 event handled successfully")

	return resp, nil
}

func (handler *Handler) getTokenFromV2Event(event events.APIGatewayV2CustomAuthorizerV2Request) (string, error) {

	if len(event.IdentitySource) == 0 {
		return "", errors.New("no identity source found in event")
	}

	if strings.Count(event.IdentitySource[0], " ") == 0 {
		return event.IdentitySource[0], nil
	}

	return strings.Split(event.IdentitySource[0], " ")[1], nil
}
