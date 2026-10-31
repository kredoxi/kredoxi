// Package synthetic generates ephemeral test credentials, never a production CA.
package synthetic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/url"
	"time"
)

type PKI struct {
	root  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func NewPKI() (*PKI, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	number, err := serial()
	if err != nil {
		return nil, err
	}
	root := &x509.Certificate{
		SerialNumber: number, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &PKI{root: root, key: key, roots: roots}, nil
}

func (p *PKI) certificate(principal string, server bool) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	number, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := &x509.Certificate{
		SerialNumber: number, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(15 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if server {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		identity, err := url.Parse(principal)
		if err != nil {
			return tls.Certificate{}, err
		}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		leaf.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, p.root, &key.PublicKey, p.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func (p *PKI) ServerConfig() (*tls.Config, error) {
	certificate, err := p.certificate("", true)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate}, ClientCAs: p.roots.Clone(),
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
	}, nil
}

func (p *PKI) ClientConfig(principal string) (*tls.Config, error) {
	certificate, err := p.certificate(principal, false)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate}, RootCAs: p.roots.Clone(),
		ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	}, nil
}
