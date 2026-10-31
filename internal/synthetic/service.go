package synthetic

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const serviceTimeout = 3 * time.Second

type Service struct {
	listener   net.Listener
	server     *http.Server
	done       chan error
	mu         sync.Mutex
	closeOnce  sync.Once
	closeErr   error
	credential []byte
	challenges map[string]time.Time
}

type serviceChallenge struct {
	Challenge string `json:"challenge"`
}

type serviceProof struct {
	Challenge string `json:"challenge"`
	Proof     string `json:"proof"`
}

func StartService(credential string) (*Service, error) {
	raw, err := hex.DecodeString(credential)
	if err != nil || len(raw) != 32 || len(credential) != 64 {
		return nil, errors.New("invalid synthetic service credential")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	service := &Service{
		listener: listener, credential: []byte(credential),
		challenges: make(map[string]time.Time), done: make(chan error, 1),
	}
	service.server = &http.Server{
		Handler:           http.HandlerFunc(service.handle),
		ReadHeaderTimeout: time.Second, ReadTimeout: serviceTimeout,
		WriteTimeout: serviceTimeout, IdleTimeout: time.Second, MaxHeaderBytes: 4096,
	}
	go func() {
		err := service.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		service.done <- err
	}()
	return service, nil
}

func (s *Service) Address() string { return s.listener.Addr().String() }

func (s *Service) Close() error {
	s.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
		defer cancel()
		s.closeErr = s.server.Shutdown(ctx)
		if s.closeErr != nil {
			if err := s.server.Close(); err != nil {
				s.closeErr = errors.New("synthetic service shutdown failed")
			}
		}
		if err := <-s.done; err != nil {
			s.closeErr = errors.New("synthetic service stopped unexpectedly")
		}
	})
	return s.closeErr
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/challenge":
		s.issueChallenge(w)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/authenticate":
		s.verifyProof(w, r)
	default:
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
	}
}

func (s *Service) issueChallenge(w http.ResponseWriter) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		http.Error(w, `{"error":"service_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	challenge := hex.EncodeToString(random)
	now := time.Now()
	s.mu.Lock()
	for value, expiry := range s.challenges {
		if !expiry.After(now) {
			delete(s.challenges, value)
		}
	}
	if len(s.challenges) >= 64 {
		s.mu.Unlock()
		http.Error(w, `{"error":"service_busy"}`, http.StatusServiceUnavailable)
		return
	}
	s.challenges[challenge] = now.Add(serviceTimeout)
	s.mu.Unlock()
	if err := json.NewEncoder(w).Encode(serviceChallenge{Challenge: challenge}); err != nil {
		s.mu.Lock()
		delete(s.challenges, challenge)
		s.mu.Unlock()
	}
}

func (s *Service) verifyProof(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Content-Type")) != 1 ||
		r.Header.Get("Content-Type") != "application/json" ||
		r.ContentLength < 1 || r.ContentLength > 1024 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var proof serviceProof
	if err := decoder.Decode(&proof); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	challengeBytes, challengeErr := hex.DecodeString(proof.Challenge)
	provided, proofErr := hex.DecodeString(proof.Proof)
	if challengeErr != nil || proofErr != nil || len(challengeBytes) != 32 || len(provided) != sha256.Size {
		http.Error(w, `{"error":"authentication_denied"}`, http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	expiry, exists := s.challenges[proof.Challenge]
	delete(s.challenges, proof.Challenge)
	s.mu.Unlock()
	if !exists || !expiry.After(time.Now()) {
		http.Error(w, `{"error":"authentication_denied"}`, http.StatusUnauthorized)
		return
	}
	mac := hmac.New(sha256.New, s.credential)
	if _, err := mac.Write(challengeBytes); err != nil {
		http.Error(w, `{"error":"service_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if subtle.ConstantTimeCompare(provided, mac.Sum(nil)) != 1 {
		http.Error(w, `{"error":"authentication_denied"}`, http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func AuthenticateService(ctx context.Context, address, credential string) error {
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || host != "127.0.0.1" {
		return errors.New("invalid synthetic service address")
	}
	raw, err := hex.DecodeString(credential)
	if err != nil || len(raw) != 32 || len(credential) != 64 {
		return errors.New("invalid synthetic service credential")
	}
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: serviceTimeout}
	baseURL := "http://" + net.JoinHostPort(host, port)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/challenge", nil)
	if err != nil {
		return errors.New("synthetic_service_unavailable")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("synthetic_service_unavailable")
	}
	var challenge serviceChallenge
	decodeErr := decodeServiceJSON(response, 200, &challenge)
	if decodeErr != nil || len(challenge.Challenge) != 64 {
		return errors.New("synthetic_service_unavailable")
	}
	challengeBytes, err := hex.DecodeString(challenge.Challenge)
	if err != nil || len(challengeBytes) != 32 {
		return errors.New("synthetic_service_unavailable")
	}
	mac := hmac.New(sha256.New, []byte(credential))
	if _, err := mac.Write(challengeBytes); err != nil {
		return errors.New("synthetic_service_unavailable")
	}
	data, err := json.Marshal(serviceProof{
		Challenge: challenge.Challenge, Proof: hex.EncodeToString(mac.Sum(nil)),
	})
	if err != nil {
		return errors.New("synthetic_service_unavailable")
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/authenticate", bytes.NewReader(data))
	if err != nil {
		return errors.New("synthetic_service_unavailable")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		return errors.New("synthetic_service_unavailable")
	}
	if closeErr := response.Body.Close(); closeErr != nil {
		return errors.New("synthetic_service_unavailable")
	}
	if response.StatusCode != http.StatusNoContent ||
		response.Header.Get("Cache-Control") != "no-store" {
		return errors.New("synthetic_service_authentication_failed")
	}
	return nil
}

func decodeServiceJSON(response *http.Response, status int, output any) error {
	defer response.Body.Close()
	if response.StatusCode != status || response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" {
		return errors.New("invalid synthetic service response")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(data) > 1024 {
		return errors.New("invalid synthetic service response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("invalid synthetic service response")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid synthetic service response")
	}
	return nil
}
