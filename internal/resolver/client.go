package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
)

type Client struct {
	url       string
	http      *http.Client
	transport *http.Transport
}

func NewClient(address string, config *tls.Config) (*Client, error) {
	host, port, err := net.SplitHostPort(address)
	number, parseErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || number < 1 || number > 65535 || host != "127.0.0.1" ||
		config == nil || config.RootCAs == nil || len(config.Certificates) != 1 ||
		config.InsecureSkipVerify || config.KeyLogWriter != nil ||
		config.GetClientCertificate != nil {
		return nil, InvalidRequest
	}
	secure := config.Clone()
	secure.ServerName = "127.0.0.1"
	secure.MinVersion, secure.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	secure.NextProtos = []string{"http/1.1"}
	transport := &http.Transport{
		TLSClientConfig: secure, Proxy: nil, MaxConnsPerHost: 8,
		TLSHandshakeTimeout: operationTimeout, ResponseHeaderTimeout: operationTimeout,
		DisableKeepAlives: true, MaxResponseHeaderBytes: 4096,
	}
	return &Client{
		url: "https://" + address + "/v1/resolve", transport: transport,
		http: &http.Client{Transport: transport, Timeout: 4 * operationTimeout,
			CheckRedirect: func(r *http.Request, via []*http.Request) error { return InvalidResponse }},
	}, nil
}

func (c *Client) Close() { c.transport.CloseIdleConnections() }

func (c *Client) Resolve(ctx context.Context, text string) (value string, err error) {
	ref, err := ParseReference(text)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(request{Reference: ref.String()})
	if err != nil {
		return "", InvalidRequest
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(data))
	if err != nil {
		return "", InvalidRequest
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", Canceled
		}
		return "", BrokerUnavailable
	}
	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil && err == nil {
			value, err = "", BrokerUnavailable
		}
	}()
	if res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Cache-Control") != "no-store" {
		return "", InvalidResponse
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, 2049))
	if err != nil {
		return "", BrokerUnavailable
	}
	var output response
	if err := strictJSON(data, 2048, []string{"value", "error", "request_id"}, &output); err != nil {
		return "", InvalidResponse
	}
	if res.StatusCode != 200 {
		if output.Value != "" {
			return "", InvalidResponse
		}
		switch Category(output.Error) {
		case AuthenticationDenied, PolicyDenied, SecretNotFound, ProviderUnavailable,
			TelemetryUnavailable, BrokerBusy, InvalidRequest, InvalidReference, Canceled:
			return "", Category(output.Error)
		default:
			return "", InvalidResponse
		}
	}
	if output.Error != "" || len(output.Value) != 64 || len(output.RequestID) != 32 {
		return "", InvalidResponse
	}
	return output.Value, nil
}

type consumerConfig struct {
	Credential string `json:"credential"`
}

// Consume proves use without printing the resolved credential. An authorized
// application can still steal it; the value exists in ordinary Go memory.
func Consume(ctx context.Context, client *Client, config []byte, use func(string) error) error {
	if client == nil || use == nil {
		return InvalidRequest
	}
	var input consumerConfig
	if err := strictJSON(config, 1024, []string{"credential"}, &input); err != nil {
		return err
	}
	value, err := client.Resolve(ctx, input.Credential)
	if err != nil {
		return err
	}
	if err := use(value); err != nil {
		return errors.New("consumer_authentication_failed")
	}
	return nil
}
