package handler

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

func (h *Handler) HandleV2Event(ctx context.Context, event events.APIGatewayV2CustomAuthorizerV2Request) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	slog.Info("handling event")
	slog.Debug("event", "value", event)

	token, err := getTokenFromV2Event(event)
	if err != nil {
		slog.Error("error getting token from event", "error", err)
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, err
	}

	valid := h.s.ValidateToken(ctx, token)
	slog.Debug("token validation result", "valid", valid)

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

	slog.Info("returning policy response")
	slog.Debug("policy response", "value", resp)

	return resp, nil
}

func getTokenFromV2Event(event events.APIGatewayV2CustomAuthorizerV2Request) (string, error) {

	if len(event.IdentitySource) == 0 {
		return "", errors.New("no identity source found in event")
	}

	if strings.Count(event.IdentitySource[0], " ") == 0 {
		return event.IdentitySource[0], nil
	}

	return strings.Split(event.IdentitySource[0], " ")[1], nil
}
