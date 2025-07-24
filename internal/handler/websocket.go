package handler

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

func (h *Handler) HandleWebsocketEvent(ctx context.Context, event events.APIGatewayWebsocketProxyRequest) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	slog.Info("handling event")
	slog.Debug("event", "value", event)

	token, err := getTokenFromWebsocketEvent(event)
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

func getTokenFromWebsocketEvent(event events.APIGatewayWebsocketProxyRequest) (string, error) {
	if event.Headers["Authorization"] != "" {
		return strings.Split(event.Headers["Authorization"], " ")[1], nil
	}

	return "", errors.New("no token found in event")
}
