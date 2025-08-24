package handler

import (
	"context"
	"testing"

	"github.com/matt-gp/oidc-authorizer/internal/otel"

	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
)

func TestNew(t *testing.T) {
	// Setup OpenTelemetry components for testing
	provider, err := otel.NewProvider()
	if err != nil {
		t.Fatalf("failed to create OpenTelemetry provider: %v", err)
	}
	defer func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("failed to shutdown OpenTelemetry provider: %v", err)
		}
	}()

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

// setupOtelForTest creates OpenTelemetry components for testing
func setupOtelForTest(t *testing.T) func() {
	provider, err := otel.NewProvider()
	if err != nil {
		t.Fatalf("failed to create OpenTelemetry provider: %v", err)
	}

	return func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("failed to shutdown OpenTelemetry provider: %v", err)
		}
	}
}
