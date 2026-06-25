package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/matt-gp/core/logger"

	"github.com/aws/aws-lambda-go/events"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	errAttrKey             = "error"
	v1EventTypeAttr        = attribute.String("event.type", "v1")
	v2EventTypeAttr        = attribute.String("event.type", "v2")
	websocketEventTypeAttr = attribute.String("event.type", "websocket")
)

type AuthEvent struct {
	Version string `json:"version,omitempty"`
}

// Service defines the interface for token validation.
//
//go:generate mockgen -package handler -source handler.go -destination handler_mock.go
type Service interface {
	ValidateToken(ctx context.Context, token string) bool
	GetPrincipalID() string
}

type Handler struct {
	service             Service
	tracer              trace.Tracer
	eventHandlerCounter metric.Int64Counter
	eventHandlerLatency metric.Float64Histogram
}

// New creates a new Handler with the provided meter, tracer, and service.
func New(meter metric.Meter, tracer trace.Tracer, service Service) (*Handler, error) {

	eventHandlerCounter, err := meter.Int64Counter(
		"oidc_authorizer.invocations",
		metric.WithDescription("Number of authorizer invocations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create invocations counter: %w", err)
	}

	eventHandlerLatency, err := meter.Float64Histogram(
		"oidc_authorizer.request.duration",
		metric.WithDescription("Duration of authorizer invocations"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request duration histogram: %w", err)
	}

	return &Handler{
		service:             service,
		tracer:              tracer,
		eventHandlerCounter: eventHandlerCounter,
		eventHandlerLatency: eventHandlerLatency,
	}, nil
}

// RouteEvent routes the incoming event to the appropriate handler based on its version. It supports v1, v2, and WebSocket events.
func (h *Handler) RouteEvent(ctx context.Context, event any) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	eventJson, err := json.Marshal(event)
	if err != nil {
		logger.Error(ctx, "error marshalling event", attribute.String(errAttrKey, err.Error()))
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error marshalling event: %w", err)
	}

	var authEvent AuthEvent
	if err := json.Unmarshal(eventJson, &authEvent); err != nil {
		logger.Error(ctx, "error unmarshalling event", attribute.String(errAttrKey, err.Error()))
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling event: %w", err)
	}

	start := time.Now()
	var (
		resp          events.APIGatewayV2CustomAuthorizerIAMPolicyResponse
		handlerErr    error
		eventTypeAttr attribute.KeyValue
	)

	switch authEvent.Version {
	case "1.0":
		eventTypeAttr = v1EventTypeAttr
		var v1Event events.APIGatewayV2CustomAuthorizerV1Request
		if err := json.Unmarshal(eventJson, &v1Event); err != nil {
			logger.Error(ctx, "error unmarshalling event", eventTypeAttr, attribute.String(errAttrKey, err.Error()))
			handlerErr = fmt.Errorf("error unmarshalling event: %w", err)
		} else {
			resp, handlerErr = h.handleEvent(ctx, v1Event, eventTypeAttr)
		}

	case "2.0":
		eventTypeAttr = v2EventTypeAttr
		var v2Event events.APIGatewayV2CustomAuthorizerV2Request
		if err := json.Unmarshal(eventJson, &v2Event); err != nil {
			logger.Error(ctx, "error unmarshalling event", eventTypeAttr, attribute.String(errAttrKey, err.Error()))
			handlerErr = fmt.Errorf("error unmarshalling event: %w", err)
		} else {
			resp, handlerErr = h.handleEvent(ctx, v2Event, eventTypeAttr)
		}

	default:
		eventTypeAttr = websocketEventTypeAttr
		var websocketEvent events.APIGatewayWebsocketProxyRequest
		if err := json.Unmarshal(eventJson, &websocketEvent); err != nil {
			logger.Error(ctx, "error unmarshalling event", eventTypeAttr, attribute.String(errAttrKey, err.Error()))
			handlerErr = fmt.Errorf("error unmarshalling event: %w", err)
		} else {
			resp, handlerErr = h.handleEvent(ctx, websocketEvent, eventTypeAttr)
		}
	}

	statusAttr := attribute.String("status", "success")
	if handlerErr != nil {
		statusAttr = attribute.String("status", "error")
	}
	h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(statusAttr, eventTypeAttr))
	h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(statusAttr, eventTypeAttr))

	return resp, handlerErr
}

// handleEvent processes the incoming event, validates the token, and returns the appropriate IAM policy response.
func (h *Handler) handleEvent(ctx context.Context, event any, eventTypeAttr attribute.KeyValue) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	ctx, span := h.tracer.Start(ctx, eventTypeAttr.Value.AsString())
	defer span.End()

	span.SetAttributes(eventTypeAttr)

	logger.Info(ctx, "handling event", eventTypeAttr)

	token, err := h.getTokenFromEvent(event)
	if err != nil {
		logger.Error(ctx, "error getting token from event", eventTypeAttr, attribute.String(errAttrKey, err.Error()))
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, err
	}

	valid := h.service.ValidateToken(ctx, token)
	logger.Debug(ctx, "token validation result", eventTypeAttr, attribute.Bool("valid", valid))

	policyEffect := "Deny"
	if valid {
		policyEffect = "Allow"
	}

	resp := events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{
		PrincipalID: h.service.GetPrincipalID(),
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
			"principalId": h.service.GetPrincipalID(),
			"valid":       valid,
		},
	}

	logger.Info(ctx, "returning policy response", eventTypeAttr)
	logger.Debug(ctx, fmt.Sprintf("policy response created: %+v", resp), eventTypeAttr)

	span.SetAttributes(attribute.Bool("valid", valid))
	span.SetStatus(codes.Ok, "event handled successfully")

	return resp, nil
}

func (h *Handler) getTokenFromEvent(event any) (string, error) {

	if wsEvent, ok := event.(events.APIGatewayWebsocketProxyRequest); ok {
		auth := wsEvent.Headers["Authorization"]
		if auth == "" {
			return "", errors.New("no token found in event")
		}

		if strings.Count(auth, " ") == 0 {
			return auth, nil
		}

		return strings.Split(auth, " ")[1], nil
	}

	if v1Event, ok := event.(events.APIGatewayV2CustomAuthorizerV1Request); ok {
		if v1Event.IdentitySource == "" {
			return "", errors.New("no identity source found in event")
		}

		if strings.Count(v1Event.IdentitySource, " ") == 0 {
			return v1Event.IdentitySource, nil
		}

		return strings.Split(v1Event.IdentitySource, " ")[1], nil
	}

	if v2Event, ok := event.(events.APIGatewayV2CustomAuthorizerV2Request); ok {
		if len(v2Event.IdentitySource) == 0 {
			return "", errors.New("no identity source found in event")
		}

		if strings.Count(v2Event.IdentitySource[0], " ") == 0 {
			return v2Event.IdentitySource[0], nil
		}

		return strings.Split(v2Event.IdentitySource[0], " ")[1], nil
	}

	return "", errors.New("unsupported event type")
}
