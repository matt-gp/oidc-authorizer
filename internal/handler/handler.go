package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/matt-gp/core/logger"

	"github.com/aws/aws-lambda-go/events"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var errAttrKey = "error"

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
	s                   Service
	logger              log.Logger
	tracer              trace.Tracer
	eventHandlerCounter metric.Int64Counter
	eventHandlerLatency metric.Float64Histogram
}

func New(logger log.Logger, meter metric.Meter, tracer trace.Tracer, s Service) (*Handler, error) {

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

	h := Handler{
		s:                   s,
		logger:              logger,
		tracer:              tracer,
		eventHandlerCounter: eventHandlerCounter,
		eventHandlerLatency: eventHandlerLatency,
	}
	return &h, nil
}

func (h *Handler) RouteEvent(ctx context.Context, event any) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {

	eventJson, err := json.Marshal(event)
	if err != nil {
		logger.Error(ctx, h.logger, "error marshalling event", attribute.String(errAttrKey, err.Error()))
		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error marshalling event: %w", err)
	}

	var authEvent AuthEvent
	if err := json.Unmarshal(eventJson, &authEvent); err != nil {
		logger.Error(ctx, h.logger, "error unmarshalling event", attribute.String(errAttrKey, err.Error()))
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
			logger.Error(ctx, h.logger, "error unmarshalling event", eventTypeAttr, attribute.String(errAttrKey, err.Error()))
			handlerErr = fmt.Errorf("error unmarshalling event: %w", err)
		} else {
			resp, handlerErr = h.HandleV1Event(ctx, v1Event)
		}

	case "2.0":
		eventTypeAttr = v2EventTypeAttr
		var v2Event events.APIGatewayV2CustomAuthorizerV2Request
		if err := json.Unmarshal(eventJson, &v2Event); err != nil {
			logger.Error(ctx, h.logger, "error unmarshalling event", eventTypeAttr, attribute.String(errAttrKey, err.Error()))
			handlerErr = fmt.Errorf("error unmarshalling event: %w", err)
		} else {
			resp, handlerErr = h.HandleV2Event(ctx, v2Event)
		}

	default:
		eventTypeAttr = websocketEventTypeAttr
		var websocketEvent events.APIGatewayWebsocketProxyRequest
		if err := json.Unmarshal(eventJson, &websocketEvent); err != nil {
			logger.Error(ctx, h.logger, "error unmarshalling event", eventTypeAttr, attribute.String(errAttrKey, err.Error()))
			handlerErr = fmt.Errorf("error unmarshalling event: %w", err)
		} else {
			resp, handlerErr = h.HandleWebsocketEvent(ctx, websocketEvent)
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
