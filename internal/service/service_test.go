// nolint
package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"oidc-authorizer/internal/otel"
	"testing"
	"time"

	jwCert "github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
)

// setupOtelForTest creates OpenTelemetry components for testing
func setupOtelForTest(t *testing.T) func() {
	provider, err := otel.NewProvider()
	if err != nil {
		t.Fatalf("failed to create OpenTelemetry provider: %v", err)
	}

	return func() {
		provider.Shutdown(context.Background())
	}
}

func createCaCertificate() (*x509.Certificate, *rsa.PrivateKey, *bytes.Buffer, *bytes.Buffer) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2021),
		Subject: pkix.Name{
			Organization: []string{"Alai"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Generate a new RSA private key
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)

	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		fmt.Printf("failed to encode certificate: %s\n", err)
		return nil, nil, nil, nil
	}

	caPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(caPrivKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)}); err != nil {
		fmt.Printf("failed to encode private key: %s\n", err)
		return nil, nil, nil, nil
	}

	return ca, caPrivKey, caPEM, caPrivKeyPEM
}

func createx509Certificate(ca *x509.Certificate, caPrivKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, *bytes.Buffer, *bytes.Buffer) {

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			Organization: []string{"Alai"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Generate a new RSA private key
	certPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certBytes, _ := x509.CreateCertificate(
		rand.Reader,
		cert,
		ca,
		&certPrivKey.PublicKey,
		caPrivKey,
	)

	// Create a new buffer to store the PEM encoded certificate
	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		fmt.Printf("failed to encode certificate: %s\n", err)
		return nil, nil, nil, nil
	}

	certPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(certPrivKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey)}); err != nil {
		fmt.Printf("failed to encode private key: %s\n", err)
		return nil, nil, nil, nil
	}

	return cert, certPrivKey, certPEM, certPrivKeyPEM
}

func createJWKSServer(cert x509.Certificate, certPem bytes.Buffer, keyID string) *httptest.Server {

	key, err := jwk.ParseKey(certPem.Bytes(), jwk.WithPEM(true))
	if err != nil {
		fmt.Printf("failed to parse JWK: %s\n", err)
		return nil
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		fmt.Printf("failed to set key ID: %s\n", err)
		return nil
	}

	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		fmt.Printf("failed to set algorithm: %s\n", err)
		return nil
	}

	if err := key.Set(jwk.KeyUsageKey, jwk.ForSignature.String()); err != nil {
		fmt.Printf("failed to set key usage: %s\n", err)
		return nil
	}

	certChain := &jwCert.Chain{}
	if err := certChain.Add(cert.Raw); err != nil {
		fmt.Printf("failed to add certificate to chain: %s\n", err)
		return nil
	}

	if err := key.Set(jwk.X509CertChainKey, certChain); err != nil {
		fmt.Printf("failed to set X.509 cert chain: %s\n", err)
		return nil
	}

	thumbprint := sha256.Sum256(certPem.Bytes())
	if err := key.Set(jwk.X509CertThumbprintS256Key, base64.StdEncoding.EncodeToString(thumbprint[:])); err != nil {
		fmt.Printf("failed to set X.509 cert thumbprint: %s\n", err)
		return nil
	}

	keyset := jwk.NewSet()
	if err := keyset.AddKey(key); err != nil {
		fmt.Printf("failed to add key to keyset: %s\n", err)
		return nil
	}

	jsonPayload, err := json.Marshal(keyset)
	if err != nil {
		fmt.Printf("failed to marshal JWK: %s\n", err)
		return nil
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, string(jsonPayload))
	}))
}

func TestNew(t *testing.T) {
	cleanup := setupOtelForTest(t)
	defer cleanup()

	logger := global.GetLoggerProvider().Logger("test")
	meter := otelapi.GetMeterProvider().Meter("test")
	tracer := otelapi.GetTracerProvider().Tracer("test")

	type test struct {
		acceptedIssuers   string
		jwksUri           string
		principalIdClaims string
	}

	tests := []test{
		{
			acceptedIssuers:   fmt.Sprintf("https://%s.com", rand.Text()),
			jwksUri:           fmt.Sprintf("https://%s.com/jwks", rand.Text()),
			principalIdClaims: "sub",
		},
		{
			acceptedIssuers:   fmt.Sprintf("https://%s.com", rand.Text()),
			jwksUri:           fmt.Sprintf("https://%s.com/jwks", rand.Text()),
			principalIdClaims: "email",
		},
	}

	for _, tc := range tests {

		s, err := New(logger, meter, tracer, tc.acceptedIssuers, tc.jwksUri, tc.principalIdClaims)
		require.NoError(t, err)
		assert.NotNil(t, s)
		assert.Equal(t, tc.acceptedIssuers, s.AcceptedIssuers)
		assert.Equal(t, tc.jwksUri, s.JwksUri)
		assert.Equal(t, tc.principalIdClaims, s.PrincipalIDClaims)
	}
}

func TestGetPrincipalID(t *testing.T) {
	cleanup := setupOtelForTest(t)
	defer cleanup()

	logger := global.GetLoggerProvider().Logger("test")
	meter := otelapi.GetMeterProvider().Meter("test")
	tracer := otelapi.GetTracerProvider().Tracer("test")

	s, err := New(logger, meter, tracer, "https://example.com", "https://example.com/jwks", "sub")
	require.NoError(t, err)
	s.PrincipalID = rand.Text()
	assert.Equal(t, s.PrincipalID, s.GetPrincipalID())
}

func TestValidate(t *testing.T) {
	cleanup := setupOtelForTest(t)
	defer cleanup()

	logger := global.GetLoggerProvider().Logger("test")
	meter := otelapi.GetMeterProvider().Meter("test")
	tracer := otelapi.GetTracerProvider().Tracer("test")

	t.Run("valid token", func(t *testing.T) {

		issuer := fmt.Sprintf("http://%s.com", rand.Text())
		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, certPrivKeyPEM := createx509Certificate(caCert, caPrivKey)

		keyID := fmt.Sprintf("sso_oidc_key_pair_%s", rand.Text())

		jwksServer := createJWKSServer(*cert, *certPem, keyID)
		defer jwksServer.Close()

		token, _ := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Subject(fmt.Sprintf("user_%s", rand.Text())).
			Expiration(time.Now().Add(time.Hour)).
			Build()

		signingKey, err := jwk.ParseKey(certPrivKeyPEM.Bytes(), jwk.WithPEM(true))
		if err != nil {
			t.Fatalf("failed to create JWK from private key: %s", err)
		}

		if err := signingKey.Set(jwk.KeyIDKey, keyID); err != nil {
			t.Fatalf("failed to set key ID: %s", err)
		}

		if err := signingKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			t.Fatalf("failed to set algorithm: %s", err)
		}

		certChain := &jwCert.Chain{}
		if err := certChain.Add(cert.Raw); err != nil {
			t.Fatalf("failed to add certificate to chain: %s\n", err)
		}

		if err := signingKey.Set(jwk.X509CertChainKey, certChain); err != nil {
			t.Fatalf("failed to set X.509 cert chain: %s", err)
		}

		thumbprint := sha256.Sum256(certPem.Bytes())
		if err := signingKey.Set(jwk.X509CertThumbprintS256Key, base64.StdEncoding.EncodeToString(thumbprint[:])); err != nil {
			t.Fatalf("failed to set X.509 cert thumbprint: %s", err)
		}

		tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
		if err != nil {
			t.Fatalf("failed to sign token: %s", err)
		}

		s, err := New(logger, meter, tracer, issuer, jwksServer.URL, "sub")
		assert.True(t, s.ValidateToken(context.Background(), string(tokenString)))
	})

	t.Run("invalid token", func(t *testing.T) {
		issuer := fmt.Sprintf("http://%s.com", rand.Text())
		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, _ := createx509Certificate(caCert, caPrivKey)

		keyID := fmt.Sprintf("sso_oidc_key_pair_%s", rand.Text())

		jwksServer := createJWKSServer(*cert, *certPem, keyID)
		defer jwksServer.Close()

		s, err := New(logger, meter, tracer, issuer, jwksServer.URL, "sub")
		require.NoError(t, err)
		assert.False(t, s.ValidateToken(context.Background(), rand.Text()))
	})

	t.Run("invalid token signature", func(t *testing.T) {

		issuer := fmt.Sprintf("http://%s.com", rand.Text())
		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, _ := createx509Certificate(caCert, caPrivKey)

		keyID := fmt.Sprintf("sso_oidc_key_pair_%s", rand.Text())

		jwksServer := createJWKSServer(*cert, *certPem, keyID)
		defer jwksServer.Close()

		token, _ := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Subject(fmt.Sprintf("user_%s", rand.Text())).
			Expiration(time.Now().Add(time.Hour)).
			Build()

		wrongPrivateKey, pkerr := rsa.GenerateKey(rand.Reader, 2048)
		if pkerr != nil {
			t.Fatal("Private key generation error", pkerr)
		}

		tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), wrongPrivateKey))
		if err != nil {
			t.Fatalf("failed to sign token: %s", err)
		}

		s, err := New(logger, meter, tracer, issuer, jwksServer.URL, "sub")
		assert.False(t, s.ValidateToken(context.Background(), string(tokenString)))
	})

	t.Run("expired token", func(t *testing.T) {

		issuer := fmt.Sprintf("http://%s.com", rand.Text())
		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, certPrivKeyPEM := createx509Certificate(caCert, caPrivKey)

		keyID := fmt.Sprintf("sso_oidc_key_pair_%s", rand.Text())

		jwksServer := createJWKSServer(*cert, *certPem, keyID)
		defer jwksServer.Close()

		token, _ := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Subject(fmt.Sprintf("user_%s", rand.Text())).
			Expiration(time.Now().Add(-time.Hour)).
			Build()

		signingKey, err := jwk.ParseKey(certPrivKeyPEM.Bytes(), jwk.WithPEM(true))
		if err != nil {
			t.Fatalf("failed to create JWK from private key: %s", err)
		}

		if err := signingKey.Set(jwk.KeyIDKey, keyID); err != nil {
			t.Fatalf("failed to set key ID: %s", err)
		}

		if err := signingKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			t.Fatalf("failed to set algorithm: %s", err)
		}

		certChain := &jwCert.Chain{}
		if err := certChain.Add(cert.Raw); err != nil {
			t.Fatalf("failed to add certificate to chain: %s\n", err)
		}

		if err := signingKey.Set(jwk.X509CertChainKey, certChain); err != nil {
			t.Fatalf("failed to set X.509 cert chain: %s", err)
		}

		thumbprint := sha256.Sum256(certPem.Bytes())
		if err := signingKey.Set(jwk.X509CertThumbprintS256Key, base64.StdEncoding.EncodeToString(thumbprint[:])); err != nil {
			t.Fatalf("failed to set X.509 cert thumbprint: %s", err)
		}

		tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
		if err != nil {
			t.Fatalf("failed to sign token: %s", err)
		}

		s, err := New(logger, meter, tracer, issuer, jwksServer.URL, "sub")
		assert.False(t, s.ValidateToken(context.Background(), string(tokenString)))
	})

	t.Run("invalid jwks url", func(t *testing.T) {
		issuer := fmt.Sprintf("http://%s.com", rand.Text())
		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, _ := createx509Certificate(caCert, caPrivKey)

		keyID := fmt.Sprintf("sso_oidc_key_pair_%s", rand.Text())

		jwksServer := createJWKSServer(*cert, *certPem, keyID)
		defer jwksServer.Close()

		s, err := New(logger, meter, tracer, issuer, fmt.Sprintf("http://%s.com", rand.Text()), "sub")
		require.NoError(t, err)
		assert.False(t, s.ValidateToken(context.Background(), rand.Text()))
	})

	t.Run("invalid kid", func(t *testing.T) {

		issuer := fmt.Sprintf("http://%s.com", rand.Text())
		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, certPrivKeyPEM := createx509Certificate(caCert, caPrivKey)

		jwksServer := createJWKSServer(*cert, *certPem, rand.Text())
		defer jwksServer.Close()

		token, _ := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Subject(fmt.Sprintf("user_%s", rand.Text())).
			Expiration(time.Now().Add(time.Hour)).
			Build()

		signingKey, err := jwk.ParseKey(certPrivKeyPEM.Bytes(), jwk.WithPEM(true))
		if err != nil {
			t.Fatalf("failed to create JWK from private key: %s", err)
		}

		if err := signingKey.Set(jwk.KeyIDKey, rand.Text()); err != nil {
			t.Fatalf("failed to set key ID: %s", err)
		}

		if err := signingKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			t.Fatalf("failed to set algorithm: %s", err)
		}

		certChain := &jwCert.Chain{}
		if err := certChain.Add(cert.Raw); err != nil {
			t.Fatalf("failed to add certificate to chain: %s\n", err)
		}

		if err := signingKey.Set(jwk.X509CertChainKey, certChain); err != nil {
			t.Fatalf("failed to set X.509 cert chain: %s", err)
		}

		thumbprint := sha256.Sum256(certPem.Bytes())
		if err := signingKey.Set(jwk.X509CertThumbprintS256Key, base64.StdEncoding.EncodeToString(thumbprint[:])); err != nil {
			t.Fatalf("failed to set X.509 cert thumbprint: %s", err)
		}

		tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
		if err != nil {
			t.Fatalf("failed to sign token: %s", err)
		}

		s, err := New(logger, meter, tracer, issuer, jwksServer.URL, "sub")
		assert.False(t, s.ValidateToken(context.Background(), string(tokenString)))
	})

	t.Run("invalid issuer", func(t *testing.T) {

		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, certPrivKeyPEM := createx509Certificate(caCert, caPrivKey)

		keyID := fmt.Sprintf("sso_oidc_key_pair_%s", rand.Text())

		jwksServer := createJWKSServer(*cert, *certPem, keyID)
		defer jwksServer.Close()

		token, _ := jwt.NewBuilder().
			Issuer(fmt.Sprintf("http://%s.com", rand.Text())).
			IssuedAt(time.Now()).
			Subject(fmt.Sprintf("user_%s", rand.Text())).
			Expiration(time.Now().Add(time.Hour)).
			Build()

		signingKey, err := jwk.ParseKey(certPrivKeyPEM.Bytes(), jwk.WithPEM(true))
		if err != nil {
			t.Fatalf("failed to create JWK from private key: %s", err)
		}

		if err := signingKey.Set(jwk.KeyIDKey, keyID); err != nil {
			t.Fatalf("failed to set key ID: %s", err)
		}

		if err := signingKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			t.Fatalf("failed to set algorithm: %s", err)
		}

		certChain := &jwCert.Chain{}
		if err := certChain.Add(cert.Raw); err != nil {
			t.Fatalf("failed to add certificate to chain: %s\n", err)
		}

		if err := signingKey.Set(jwk.X509CertChainKey, certChain); err != nil {
			t.Fatalf("failed to set X.509 cert chain: %s", err)
		}

		thumbprint := sha256.Sum256(certPem.Bytes())
		if err := signingKey.Set(jwk.X509CertThumbprintS256Key, base64.StdEncoding.EncodeToString(thumbprint[:])); err != nil {
			t.Fatalf("failed to set X.509 cert thumbprint: %s", err)
		}

		tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
		if err != nil {
			t.Fatalf("failed to sign token: %s", err)
		}

		s, err := New(logger, meter, tracer, fmt.Sprintf("http://%s.com", rand.Text()), jwksServer.URL, "sub")
		assert.False(t, s.ValidateToken(context.Background(), string(tokenString)))
	})

	t.Run("invalid principal", func(t *testing.T) {

		issuer := fmt.Sprintf("http://%s.com", rand.Text())
		caCert, caPrivKey, _, _ := createCaCertificate()
		cert, _, certPem, certPrivKeyPEM := createx509Certificate(caCert, caPrivKey)

		keyID := fmt.Sprintf("sso_oidc_key_pair_%s", rand.Text())

		jwksServer := createJWKSServer(*cert, *certPem, keyID)
		defer jwksServer.Close()

		token, _ := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(time.Now()).
			Subject(fmt.Sprintf("user_%s", rand.Text())).
			Expiration(time.Now().Add(time.Hour)).
			Build()

		signingKey, err := jwk.ParseKey(certPrivKeyPEM.Bytes(), jwk.WithPEM(true))
		if err != nil {
			t.Fatalf("failed to create JWK from private key: %s", err)
		}

		if err := signingKey.Set(jwk.KeyIDKey, keyID); err != nil {
			t.Fatalf("failed to set key ID: %s", err)
		}

		if err := signingKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
			t.Fatalf("failed to set algorithm: %s", err)
		}

		certChain := &jwCert.Chain{}
		if err := certChain.Add(cert.Raw); err != nil {
			t.Fatalf("failed to add certificate to chain: %s\n", err)
		}

		if err := signingKey.Set(jwk.X509CertChainKey, certChain); err != nil {
			t.Fatalf("failed to set X.509 cert chain: %s", err)
		}

		thumbprint := sha256.Sum256(certPem.Bytes())
		if err := signingKey.Set(jwk.X509CertThumbprintS256Key, base64.StdEncoding.EncodeToString(thumbprint[:])); err != nil {
			t.Fatalf("failed to set X.509 cert thumbprint: %s", err)
		}

		tokenString, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), signingKey))
		if err != nil {
			t.Fatalf("failed to sign token: %s", err)
		}

		s, err := New(logger, meter, tracer, issuer, jwksServer.URL, "id")
		assert.False(t, s.ValidateToken(context.Background(), string(tokenString)))
	})
}
