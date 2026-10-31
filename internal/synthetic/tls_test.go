package synthetic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
