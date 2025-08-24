package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"oidc-authorizer/internal/logger"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
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
	s                   Service
	logger              log.Logger
	meter               metric.Meter
	tracer              trace.Tracer
	eventHandlerCounter metric.Int64Counter
	eventHandlerLatency metric.Float64Histogram
}

func New(logger log.Logger, meter metric.Meter, tracer trace.Tracer, s Service) (*Handler, error) {

	eventHandlerCounter, err := meter.Int64Counter(
		"oidc_authorizer_event_handler_total",
		metric.WithDescription("Total number of event handler invocations"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create event handler counter: %w", err)
	}

	eventHandlerLatency, err := meter.Float64Histogram(
		"oidc_authorizer_event_handler_latency",
		metric.WithDescription("Latency of event handler invocations"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create event handler latency histogram: %w", err)
	}

	h := Handler{
		s:                   s,
		logger:              logger,
		meter:               meter,
		tracer:              tracer,
		eventHandlerCounter: eventHandlerCounter,
		eventHandlerLatency: eventHandlerLatency,
	}
	return &h, nil
}

func (h *Handler) RouteEvent(ctx context.Context, event any) (events.APIGatewayV2CustomAuthorizerIAMPolicyResponse, error) {
	start := time.Now()

	// Start tracing
	ctx, span := h.tracer.Start(ctx, "route-event")
	defer span.End()

	logger.Debug(ctx, h.logger, "routing event")

	eventJson, err := json.Marshal(event)
	if err != nil {

		logger.Error(ctx, h.logger, "error marshalling event", logger.Err(err))

		attributes := []attribute.KeyValue{
			attribute.String("status", "error"),
			attribute.String("event.type", "marshalling"),
		}

		h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
		h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

		span.SetAttributes(attributes...)
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error marshalling event: %w", err)
	}

	var authEvent AuthEvent
	if err := json.Unmarshal(eventJson, &authEvent); err != nil {

		logger.Error(ctx, h.logger, "error unmarshalling event", logger.Err(err))

		attributes := []attribute.KeyValue{
			attribute.String("status", "error"),
			attribute.String("event.type", "unmarshalling"),
		}

		h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
		h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

		span.SetAttributes(attributes...)
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling event: %w", err)
	}

	if authEvent.Version == "1.0" {

		logger.Debug(ctx, h.logger, "routing v1 event")

		var v1Event events.APIGatewayV2CustomAuthorizerV1Request

		if err := json.Unmarshal(eventJson, &v1Event); err != nil {

			logger.Error(ctx, h.logger, "error unmarshalling v1 event", logger.Err(err))

			attributes := []attribute.KeyValue{
				attribute.String("status", "error"),
				attribute.String("event.type", "v1"),
			}

			h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
			h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

			span.SetAttributes(attributes...)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)

			return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling v1 event: %w", err)
		}

		attributes := []attribute.KeyValue{
			attribute.String("status", "success"),
			attribute.String("event.type", "v1"),
		}

		h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
		h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

		span.SetAttributes(attributes...)
		span.SetStatus(codes.Ok, "event v1 routed successfully")

		return h.HandleV1Event(ctx, v1Event)
	}

	var v2Event events.APIGatewayV2CustomAuthorizerV2Request

	if authEvent.Version == "2.0" {

		logger.Debug(ctx, h.logger, "routing v2 event")

		if err := json.Unmarshal(eventJson, &v2Event); err != nil {

			logger.Error(ctx, h.logger, "error unmarshalling v2 event", logger.Err(err))

			attributes := []attribute.KeyValue{
				attribute.String("status", "error"),
				attribute.String("event.type", "v2"),
			}

			h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
			h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

			span.SetAttributes(attributes...)
			span.SetStatus(codes.Error, err.Error())
			span.RecordError(err)

			return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling v2 event: %w", err)
		}

		attributes := []attribute.KeyValue{
			attribute.String("status", "success"),
			attribute.String("event.type", "v2"),
		}

		h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
		h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

		span.SetAttributes(attributes...)
		span.SetStatus(codes.Ok, "event v2 routed successfully")

		return h.HandleV2Event(ctx, v2Event)
	}

	logger.Debug(ctx, h.logger, "routing websocket event")

	var websocketEvent events.APIGatewayWebsocketProxyRequest

	if err := json.Unmarshal(eventJson, &websocketEvent); err != nil {

		logger.Error(ctx, h.logger, "error unmarshalling websocket event", logger.Err(err))

		attributes := []attribute.KeyValue{
			attribute.String("status", "error"),
			attribute.String("event.type", "websocket"),
		}

		h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
		h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

		span.SetAttributes(attributes...)
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)

		return events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, fmt.Errorf("error unmarshalling websocket event: %w", err)
	}

	attributes := []attribute.KeyValue{
		attribute.String("status", "success"),
		attribute.String("event.type", "websocket"),
	}

	h.eventHandlerCounter.Add(ctx, 1, metric.WithAttributes(attributes...))
	h.eventHandlerLatency.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attributes...))

	span.SetAttributes(attributes...)
	span.SetStatus(codes.Ok, "event websocket routed successfully")

	return h.HandleWebsocketEvent(ctx, websocketEvent)
}
