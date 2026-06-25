package handler

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/matt-gp/core/logger"
	"github.com/matt-gp/core/otel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	otelapi "go.opentelemetry.io/otel"
)

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

func TestNew(t *testing.T) {
	cleanup := setupOtelForTest(t)
	defer cleanup()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := NewMockService(ctrl)

	meter := otelapi.GetMeterProvider().Meter("test")
	tracer := otelapi.GetTracerProvider().Tracer("test")

	handler, err := New(meter, tracer, mockService)
	require.NoError(t, err)
	assert.NotNil(t, handler)
}

func TestHandleEvent(t *testing.T) {
	tests := []struct {
		name             string
		event            any
		token            string
		tokenValid       bool
		expectError      bool
		expectedErrorMsg string
		expectedEffect   string
		expectValidInCtx bool
		setupMock        func(*MockService, string)
	}{
		{
			name: "v1 valid token",
			event: events.APIGatewayV2CustomAuthorizerV1Request{
				IdentitySource: "Bearer valid-token",
				Version:        "1.0",
			},
			token:            "valid-token",
			tokenValid:       true,
			expectError:      false,
			expectedEffect:   "Allow",
			expectValidInCtx: true,
		},
		{
			name: "v1 invalid token",
			event: events.APIGatewayV2CustomAuthorizerV1Request{
				IdentitySource: "Bearer invalid-token",
				Version:        "1.0",
			},
			token:            "invalid-token",
			tokenValid:       false,
			expectError:      false,
			expectedEffect:   "Deny",
			expectValidInCtx: false,
		},
		{
			name: "v1 no token",
			event: events.APIGatewayV2CustomAuthorizerV1Request{
				Version: "1.0",
			},
			expectError:      true,
			expectedErrorMsg: "no identity source found in event",
		},
		{
			name: "v2 valid token",
			event: events.APIGatewayV2CustomAuthorizerV2Request{
				IdentitySource: []string{"Bearer valid-token"},
				Version:        "2.0",
			},
			token:            "valid-token",
			tokenValid:       true,
			expectError:      false,
			expectedEffect:   "Allow",
			expectValidInCtx: true,
		},
		{
			name: "v2 invalid token",
			event: events.APIGatewayV2CustomAuthorizerV2Request{
				IdentitySource: []string{"Bearer invalid-token"},
				Version:        "2.0",
			},
			token:            "invalid-token",
			tokenValid:       false,
			expectError:      false,
			expectedEffect:   "Deny",
			expectValidInCtx: false,
		},
		{
			name: "v2 no token",
			event: events.APIGatewayV2CustomAuthorizerV2Request{
				Version: "2.0",
			},
			expectError:      true,
			expectedErrorMsg: "no identity source found in event",
		},
		{
			name: "websocket valid token",
			event: events.APIGatewayWebsocketProxyRequest{
				Headers: map[string]string{
					"Authorization": "Bearer valid-token",
				},
			},
			token:            "valid-token",
			tokenValid:       true,
			expectError:      false,
			expectedEffect:   "Allow",
			expectValidInCtx: true,
		},
		{
			name: "websocket invalid token",
			event: events.APIGatewayWebsocketProxyRequest{
				Headers: map[string]string{
					"Authorization": "Bearer invalid-token",
				},
			},
			token:            "invalid-token",
			tokenValid:       false,
			expectError:      false,
			expectedEffect:   "Deny",
			expectValidInCtx: false,
		},
		{
			name: "websocket no token",
			event: events.APIGatewayWebsocketProxyRequest{
				Headers: map[string]string{},
			},
			expectError:      true,
			expectedErrorMsg: "no token found in event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setupOtelForTest(t)
			defer cleanup()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockService := NewMockService(ctrl)
			randomPrincipalID := rand.Text()

			// Setup mock expectations
			if !tt.expectError {
				mockService.EXPECT().ValidateToken(gomock.Any(), tt.token).Return(tt.tokenValid)
				mockService.EXPECT().GetPrincipalID().Return(randomPrincipalID).Times(2)
			}

			meter := otelapi.GetMeterProvider().Meter("test")
			tracer := otelapi.GetTracerProvider().Tracer("test")

			handler, err := New(meter, tracer, mockService)
			require.NoError(t, err)

			resp, err := handler.RouteEvent(context.Background(), tt.event)

			if tt.expectError {
				require.Error(t, err)
				assert.Equal(t, tt.expectedErrorMsg, err.Error())
				assert.Empty(t, resp.PrincipalID)
			} else {
				require.NoError(t, err)
				assert.Equal(t, randomPrincipalID, resp.PrincipalID)
				assert.Equal(t, tt.expectedEffect, resp.PolicyDocument.Statement[0].Effect)
				assert.Equal(t, randomPrincipalID, resp.Context["principalId"])
				assert.Equal(t, tt.expectValidInCtx, resp.Context["valid"])
			}
		})
	}
}

func TestGetTokenFromEvent(t *testing.T) {
	tests := []struct {
		name          string
		event         any
		expectedToken string
		expectError   bool
		expectedError string
	}{
		{
			name: "v1 with Bearer prefix",
			event: events.APIGatewayV2CustomAuthorizerV1Request{
				IdentitySource: "Bearer my-token",
			},
			expectedToken: "my-token",
			expectError:   false,
		},
		{
			name: "v1 without Bearer prefix",
			event: events.APIGatewayV2CustomAuthorizerV1Request{
				IdentitySource: "raw-token",
			},
			expectedToken: "raw-token",
			expectError:   false,
		},
		{
			name: "v1 empty token",
			event: events.APIGatewayV2CustomAuthorizerV1Request{
				IdentitySource: "",
			},
			expectError:   true,
			expectedError: "no identity source found in event",
		},
		{
			name: "v2 with Bearer prefix",
			event: events.APIGatewayV2CustomAuthorizerV2Request{
				IdentitySource: []string{"Bearer my-token"},
			},
			expectedToken: "my-token",
			expectError:   false,
		},
		{
			name: "v2 without Bearer prefix",
			event: events.APIGatewayV2CustomAuthorizerV2Request{
				IdentitySource: []string{"raw-token"},
			},
			expectedToken: "raw-token",
			expectError:   false,
		},
		{
			name: "v2 empty token",
			event: events.APIGatewayV2CustomAuthorizerV2Request{
				IdentitySource: []string{},
			},
			expectError:   true,
			expectedError: "no identity source found in event",
		},
		{
			name: "websocket with Bearer prefix",
			event: events.APIGatewayWebsocketProxyRequest{
				Headers: map[string]string{
					"Authorization": "Bearer my-token",
				},
			},
			expectedToken: "my-token",
			expectError:   false,
		},
		{
			name: "websocket without Bearer prefix",
			event: events.APIGatewayWebsocketProxyRequest{
				Headers: map[string]string{
					"Authorization": "raw-token",
				},
			},
			expectedToken: "raw-token",
			expectError:   false,
		},
		{
			name: "websocket no authorization header",
			event: events.APIGatewayWebsocketProxyRequest{
				Headers: map[string]string{},
			},
			expectError:   true,
			expectedError: "no token found in event",
		},
		{
			name:          "unsupported event type",
			event:         "unsupported",
			expectError:   true,
			expectedError: "unsupported event type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanup := setupOtelForTest(t)
			defer cleanup()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockService := NewMockService(ctrl)

			meter := otelapi.GetMeterProvider().Meter("test")
			tracer := otelapi.GetTracerProvider().Tracer("test")

			handler, err := New(meter, tracer, mockService)
			require.NoError(t, err)

			token, err := handler.getTokenFromEvent(tt.event)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedToken, token)
			}
		})
	}
}
