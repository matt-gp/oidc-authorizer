package handler

import (
	"context"
	"oidc-authorizer/internal/otel"
	"testing"

	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
)

func TestNew(t *testing.T) {
	// Setup OpenTelemetry components for testing
	provider, err := otel.NewProvider()
	if err != nil {
		t.Fatalf("failed to create OpenTelemetry provider: %v", err)
	}
	defer provider.Shutdown(context.Background())

	logger := global.GetLoggerProvider().Logger("test")
	meter := otelapi.GetMeterProvider().Meter("test")
	tracer := otelapi.GetTracerProvider().Tracer("test")

	s := &MockService{}
	h, err := New(logger, meter, tracer, s)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}
	if h == nil {
		t.Errorf("expected handler to be non-nil")
	}
}
