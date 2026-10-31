package synthetic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/kredoxi/kredoxi/examples"
	"github.com/kredoxi/kredoxi/internal/resolver"
)

func TestCertificateLifetimePurposeAndSAN(t *testing.T) {
	pki, err := NewPKI()
	if err != nil {
		t.Fatal(err)
	}

	serverTLS, err := pki.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := resolver.NewPolicy(examples.Policy, sha256.Sum256([]byte(examples.TrustedPolicy)))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := resolver.NewSyntheticProvider([]string{examples.Reference})
	if err != nil {
		t.Fatal(err)
	}
	telemetry, err := resolver.NewTelemetry(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := resolver.Start(serverTLS, policy, provider, telemetry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := broker.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, mode := range []string{"expired", "future", "wrong-purpose", "multiple-uri", "missing-uri"} {
		t.Run(mode, func(t *testing.T) {
			config, err := pki.ClientConfig(examples.Principal)
			if err != nil {
				t.Fatal(err)
			}
			certificate := config.Certificates[0]
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "expired":
				leaf.NotBefore = time.Now().Add(-2 * time.Hour)
				leaf.NotAfter = time.Now().Add(-time.Hour)
			case "future":
				leaf.NotBefore = time.Now().Add(time.Hour)
				leaf.NotAfter = time.Now().Add(2 * time.Hour)
			case "wrong-purpose":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "multiple-uri":
				other, err := url.Parse("urn:kredoxi:principal:unauthorized")
				if err != nil {
					t.Fatal(err)
				}
				leaf.URIs = append(leaf.URIs, other)
			case "missing-uri":
				leaf.URIs = nil
			}
			leaf.Raw = nil
			leaf.RawTBSCertificate = nil
			leaf.Extensions = nil
			der, err := x509.CreateCertificate(rand.Reader, leaf, pki.root, leaf.PublicKey, pki.key)
			if err != nil {
				t.Fatal(err)
			}
			certificate.Certificate = [][]byte{der}
			config.Certificates[0] = certificate
			client, err := resolver.NewClient(broker.Address(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			value, err := client.Resolve(context.Background(), examples.Reference)
			if value != "" || err == nil {
				t.Fatal("invalid certificate accepted")
			}
			if mode == "multiple-uri" || mode == "missing-uri" {
				if !errors.Is(err, resolver.AuthenticationDenied) {
					t.Fatal("invalid SAN not rejected")
				}
			} else if !errors.Is(err, resolver.BrokerUnavailable) {
				t.Fatal("invalid certificate not rejected at TLS")
			}
		})
	}
}

func TestTLSMaterialBootstrapRoundTrip(t *testing.T) {
	pki, err := NewPKI()
	if err != nil {
		t.Fatal(err)
	}
	serverMaterial, err := pki.ServerMaterial()
	if err != nil {
		t.Fatal(err)
	}
	clientMaterial, err := pki.ClientMaterial(examples.Principal)
	if err != nil {
		t.Fatal(err)
	}
	serverData, err := json.Marshal(serverMaterial)
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := json.Marshal(clientMaterial)
	if err != nil {
		t.Fatal(err)
	}
	var serverCopy, clientCopy TLSMaterial
	if err := json.Unmarshal(serverData, &serverCopy); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(clientData, &clientCopy); err != nil {
		t.Fatal(err)
	}
	serverTLS, err := ServerConfigFromMaterial(serverCopy)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := ClientConfigFromMaterial(clientCopy)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := resolver.NewPolicy(examples.Policy, sha256.Sum256([]byte(examples.TrustedPolicy)))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := resolver.NewSyntheticProvider([]string{examples.Reference})
	if err != nil {
		t.Fatal(err)
	}
	telemetry, err := resolver.NewTelemetry(&bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	broker, err := resolver.Start(serverTLS, policy, provider, telemetry)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := broker.Close(); err != nil {
			t.Error(err)
		}
	}()
	client, err := resolver.NewClient(broker.Address(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if value, err := client.Resolve(context.Background(), examples.Reference); err != nil || len(value) != 64 {
		t.Fatal("round-tripped TLS material failed")
	}
}

func TestSyntheticServiceChallenge(t *testing.T) {
	credential := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	service, err := StartService(credential)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := AuthenticateService(context.Background(), service.Address(), credential); err != nil {
		t.Fatal("valid challenge proof rejected")
	}
	if err := AuthenticateService(context.Background(), service.Address(), "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"); err == nil {
		t.Fatal("invalid challenge proof accepted")
	}
	if err := AuthenticateService(context.Background(), "0.0.0.0:80", credential); err == nil {
		t.Fatal("non-loopback service address accepted")
	}
}
