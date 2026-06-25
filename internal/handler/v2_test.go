package handler

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.uber.org/mock/gomock"
)

func TestHandleV2Event(t *testing.T) {
	t.Run("valid token - header", func(t *testing.T) {
		cleanup := setupOtelForTest(t)
		defer cleanup()

		randomPrincipalID := rand.Text()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockService(ctrl)

		mockService.EXPECT().ValidateToken(gomock.Any(), "valid-token").Return(true)
		mockService.EXPECT().GetPrincipalID().Return(randomPrincipalID).Times(2)

		handler, err := New(
			otel.GetMeterProvider().Meter("test"),
			otel.GetTracerProvider().Tracer("test"),
			mockService,
		)
		require.NoError(t, err)

		event := events.APIGatewayV2CustomAuthorizerV2Request{
			IdentitySource: []string{"Bearer valid-token"},
		}

		resp, err := handler.HandleV2Event(context.Background(), event)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if resp.PrincipalID != randomPrincipalID {
			t.Errorf("expected principal ID to be 1234567890, got %s", resp.PrincipalID)
		}

		assert.Equal(t, "Allow", resp.PolicyDocument.Statement[0].Effect)
		assert.Equal(t, randomPrincipalID, resp.Context["principalId"])
		valid, ok := resp.Context["valid"].(bool)
		assert.True(t, ok && valid)
	})

	t.Run("invalid token", func(t *testing.T) {
		cleanup := setupOtelForTest(t)
		defer cleanup()

		randomPrincipalID := rand.Text()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockService(ctrl)
		mockService.EXPECT().ValidateToken(gomock.Any(), "invalid-token").Return(false)
		mockService.EXPECT().GetPrincipalID().Return(randomPrincipalID).Times(2)

		handler, err := New(
			otel.GetMeterProvider().Meter("test"),
			otel.GetTracerProvider().Tracer("test"),
			mockService,
		)
		require.NoError(t, err)

		event := events.APIGatewayV2CustomAuthorizerV2Request{
			IdentitySource: []string{"Bearer invalid-token"},
		}

		resp, err := handler.HandleV2Event(context.Background(), event)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if resp.PrincipalID != randomPrincipalID {
			t.Errorf("expected principal ID to be 1234567890, got %s", resp.PrincipalID)
		}

		assert.Equal(t, "Deny", resp.PolicyDocument.Statement[0].Effect)
		assert.Equal(t, randomPrincipalID, resp.Context["principalId"])
		valid, ok := resp.Context["valid"].(bool)
		assert.True(t, ok && !valid)
	})

	t.Run("no token", func(t *testing.T) {
		cleanup := setupOtelForTest(t)
		defer cleanup()

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockService := NewMockService(ctrl)
		handler, err := New(
			otel.GetMeterProvider().Meter("test"),
			otel.GetTracerProvider().Tracer("test"),
			mockService,
		)
		require.NoError(t, err)

		event := events.APIGatewayV2CustomAuthorizerV2Request{}

		resp, err := handler.HandleV2Event(context.Background(), event)
		assert.Equal(t, events.APIGatewayV2CustomAuthorizerIAMPolicyResponse{}, resp)
		assert.Equal(t, err.Error(), "no identity source found in event")
	})
}

func TestGetTokenFromV2Event(t *testing.T) {
	cleanup := setupOtelForTest(t)
	defer cleanup()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := NewMockService(ctrl)
	handler, err := New(otel.GetMeterProvider().Meter("test"), otel.GetTracerProvider().Tracer("test"), mockService)
	require.NoError(t, err)

	t.Run("no token", func(t *testing.T) {
		event := events.APIGatewayV2CustomAuthorizerV2Request{}
		token, err := handler.getTokenFromV2Event(event)
		assert.Empty(t, token)
		assert.Error(t, err)
		assert.Equal(t, errors.New("no identity source found in event"), err)

	})

	t.Run("no spaces", func(t *testing.T) {
		randomToken := rand.Text()
		event := events.APIGatewayV2CustomAuthorizerV2Request{
			IdentitySource: []string{randomToken},
		}
		token, err := handler.getTokenFromV2Event(event)
		assert.NoError(t, err)
		assert.Equal(t, randomToken, token)
	})

	t.Run("spaces", func(t *testing.T) {
		randomToken := rand.Text()
		event := events.APIGatewayV2CustomAuthorizerV2Request{
			IdentitySource: []string{"Bearer " + randomToken},
		}
		token, err := handler.getTokenFromV2Event(event)
		assert.NoError(t, err)
		assert.Equal(t, randomToken, token)
	})
}
