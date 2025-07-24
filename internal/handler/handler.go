package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/aws/aws-lambda-go/events"
)

// Service defines the interface for the authentication service.
//
//go:generate mockgen -package handler -source handler.go -destination handler_mock.go
type Service interface {
	ValidateToken(ctx context.Context, token string) bool
	GetPrincipalID() string
}

type AuthEvent struct {
	Version string `json:"version,omitempty"`
}

type Handler struct {
	s Service
}

func NewHandler(s Service) *Handler {
	h := Handler{
		s: s,
	}
	return &h
}

func (h *Handler) RouteEvent(ctx context.Context, event any) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {
	slog.Debug("routing event", "event", event)

	eventJson, err := json.Marshal(event)
	if err != nil {
		slog.Error("error marshalling event", "error", err)
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error marshalling event: %w", err)
	}

	var authEvent AuthEvent
	if err := json.Unmarshal(eventJson, &authEvent); err != nil {
		slog.Error("error unmarshalling event", "error", err)
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling event: %w", err)
	}

	if authEvent.Version == "1.0" {
		slog.Debug("routing v1 event")
		var v1Event events.APIGatewayV2CustomAuthorizerV1Request
		if err := json.Unmarshal(eventJson, &v1Event); err != nil {
			slog.Error("error unmarshalling v1 event", "error", err)
			return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling v1 event: %w", err)
		}
		return h.HandleV1Event(ctx, v1Event)
	}

	if authEvent.Version == "2.0" {
		slog.Debug("routing v2 event")
		var v2Event events.APIGatewayV2CustomAuthorizerV2Request
		if err := json.Unmarshal(eventJson, &v2Event); err != nil {
			slog.Error("error unmarshalling v2 event", "error", err)
			return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling v2 event: %w", err)
		}
		return h.HandleV2Event(ctx, v2Event)
	}

	slog.Debug("routing websocket event")
	var websocketEvent events.APIGatewayWebsocketProxyRequest
	if err := json.Unmarshal(eventJson, &websocketEvent); err != nil {
		slog.Error("error unmarshalling websocket event", "error", err)
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling websocket event: %w", err)
	}
	return h.HandleWebsocketEvent(ctx, websocketEvent)
}
