package handler

import (
	"context"
	"testing"

	"github.com/matt-gp/core/logger"
	"github.com/matt-gp/core/otel"

	otelapi "go.opentelemetry.io/otel"
)

func TestNew(t *testing.T) {
	// Setup OpenTelemetry components for testing
	provider, err := otel.NewProvider(context.Background())
	if err != nil {
		t.Fatalf("failed to create OpenTelemetry provider: %v", err)
	}
	defer func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("failed to shutdown OpenTelemetry provider: %v", err)
		}
	}()

	meter := otelapi.GetMeterProvider().Meter("test")
	tracer := otelapi.GetTracerProvider().Tracer("test")

	service := &MockService{}
	handler, err := New(meter, tracer, service)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}
	if handler == nil {
		t.Errorf("expected handler to be non-nil")
	}
}

// setupOtelForTest creates OpenTelemetry components for testing
func setupOtelForTest(t *testing.T) func() {
	provider, err := otel.NewProvider(context.Background())
	if err != nil {
		t.Fatalf("failed to create OpenTelemetry provider: %v", err)
	}

	// Initialize logger for tests
	logger.SetProvider(provider.LoggerProvider.Logger("test"))

	return func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("failed to shutdown OpenTelemetry provider: %v", err)
		}
	}
}
