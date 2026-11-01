//go:build linux

package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kredoxi/kredoxi/internal/synthetic"
)

type linuxPeer struct {
	uid uint32
	gid uint32
	pid int32
}

type linuxEvidence struct {
	peer   linuxPeer
	status string
}

type linuxHarness struct {
	endpoint *linuxEndpoint
	broker   *experimentBroker
	evidence chan linuxEvidence
	done     chan struct{}
}

type linuxEndpoint struct {
	listener  *net.UnixListener
	path      string
	info      os.FileInfo
	closeOnce sync.Once
	closeErr  error
}

func runNativeIPCHelper(t *testing.T) {
	t.Helper()
	path := os.Getenv("KREDOXI_IPC_ENDPOINT")
	if operation := os.Getenv("KREDOXI_IPC_TEST_OPERATION"); operation != "" {
		expectedUID := os.Getenv("KREDOXI_IPC_EXPECTED_UID")
		if expectedUID == "" || expectedUID != strconv.Itoa(os.Getuid()) {
			t.Fatal("filesystem helper did not run under the expected distinct UID")
		}
		var err error
		switch operation {
		case "rename_endpoint":
			err = os.Rename(path, os.Getenv("KREDOXI_IPC_RENAME_TARGET"))
		case "unlink_endpoint":
			err = os.Remove(path)
		default:
			t.Fatal("unknown filesystem experiment operation")
		}
		if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
			t.Fatal("different UID was not denied access to the broker endpoint namespace")
		}
		if _, err := fmt.Fprintln(os.Stdout, "ipc-helper:native=endpoint_operation_denied"); err != nil {
			t.Fatal("could not report endpoint namespace denial")
		}
		return
	}
	reference := os.Getenv("KREDOXI_IPC_REFERENCE")
	if reference == "" {
		reference = testReference
	}
	want := os.Getenv("KREDOXI_IPC_EXPECTED_STATUS")
	if want == "" {
		want = "resolved"
	}
	requestBytes, err := json.Marshal(request{
		Reference: reference, ClaimedPrincipal: "uid:0",
		ClaimedUID: 0, ClaimedPID: 1,
	})
	if err != nil {
		t.Fatal("could not encode synthetic IPC request")
	}
	got, err := linuxRequest(path, requestBytes)
	if err != nil {
		if want == "connect_denied" && errors.Is(err, syscall.EACCES) {
			if _, writeErr := fmt.Fprintln(os.Stdout, "ipc-helper:native=connect_denied"); writeErr != nil {
				t.Fatal("could not report native socket permission denial")
			}
			return
		}
		t.Fatal("native Unix socket request failed")
	}
	if got.Status != want {
		t.Fatal("native Unix socket returned an unexpected decision")
	}
	if want == "resolved" {
		wantDigest := os.Getenv("KREDOXI_IPC_EXPECTED_DIGEST")
		if wantDigest == "" || syntheticValueDigest(got.Value) != wantDigest {
			t.Fatal("native Unix socket returned an unexpected synthetic value")
		}
	}
	if _, err := fmt.Fprintf(os.Stdout, "ipc-helper:native=%s\n", want); err != nil {
		t.Fatal("could not report native IPC result")
	}
}

func newLinuxHarness(t *testing.T, directoryMode, socketMode os.FileMode) *linuxHarness {
	t.Helper()
	directory, err := os.MkdirTemp("", "kredoxi-ipc-")
	if err != nil {
		t.Fatal("could not create isolated Unix socket directory")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error("could not remove isolated Unix socket directory")
		}
	})
	if err := os.Chmod(directory, directoryMode); err != nil {
		t.Fatal("could not set isolated Unix socket directory mode")
	}
	path := filepath.Join(directory, "broker.sock")
	endpoint, err := listenLinuxEndpoint(path, socketMode)
	if err != nil {
		t.Fatal("could not create isolated Unix socket")
	}
	value, err := randomSyntheticValue()
	if err != nil {
		t.Fatal("could not generate synthetic IPC value")
	}
	harness := &linuxHarness{
		endpoint: endpoint,
		broker: newExperimentBroker(
			"uid:"+strconv.Itoa(os.Getuid()), testReference, value,
		),
		evidence: make(chan linuxEvidence, 32),
		done:     make(chan struct{}),
	}
	t.Cleanup(func() {
		if err := endpoint.close(); err != nil {
			t.Error("could not close isolated Unix socket")
		}
		select {
		case <-harness.done:
		case <-time.After(2 * time.Second):
			t.Error("Unix socket accept loop did not stop")
		}
	})
	go serveLinux(harness)
	return harness
}

func listenLinuxEndpoint(path string, mode os.FileMode) (*linuxEndpoint, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("Unix socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		return nil, errors.New("created endpoint is not a socket")
	}
	return &linuxEndpoint{listener: listener, path: path, info: info}, nil
}

func (e *linuxEndpoint) close() error {
	e.closeOnce.Do(func() {
		e.closeErr = e.listener.Close()
		current, statErr := os.Lstat(e.path)
		if statErr == nil && os.SameFile(e.info, current) {
			if err := os.Remove(e.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				e.closeErr = err
			}
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			e.closeErr = statErr
		}
	})
	return e.closeErr
}

func serveLinux(h *linuxHarness) {
	var workers sync.WaitGroup
	defer func() {
		workers.Wait()
		close(h.done)
	}()
	for {
		connection, err := h.endpoint.listener.AcceptUnix()
		if err != nil {
			return
		}
		workers.Add(1)
		go func(connection *net.UnixConn) {
			defer workers.Done()
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			peer, err := linuxPeerCredentials(connection)
			if err != nil {
				return
			}
			data, err := io.ReadAll(io.LimitReader(connection, maxRequestBytes+1))
			result := reply{Status: "invalid_request"}
			if err == nil && len(data) <= maxRequestBytes {
				result = h.broker.resolve("uid:"+strconv.FormatUint(uint64(peer.uid), 10), data)
			}
			h.evidence <- linuxEvidence{peer: peer, status: result.Status}
			if err := json.NewEncoder(connection).Encode(result); err != nil {
				return
			}
		}(connection)
	}
}

func linuxPeerCredentials(connection *net.UnixConn) (linuxPeer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return linuxPeer{}, err
	}
	var credentials *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED,
		)
	}); err != nil {
		return linuxPeer{}, err
	}
	if socketErr != nil {
		return linuxPeer{}, socketErr
	}
	return linuxPeer{uid: credentials.Uid, gid: credentials.Gid, pid: credentials.Pid}, nil
}

func linuxRequest(path string, data []byte) (reply, error) {
	var zero reply
	connection, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return zero, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return zero, err
	}
	if _, err := connection.Write(data); err != nil {
		return zero, err
	}
	if err := connection.(*net.UnixConn).CloseWrite(); err != nil {
		return zero, err
	}
	response, err := io.ReadAll(io.LimitReader(connection, 2049))
	if err != nil {
		return zero, err
	}
	if len(response) > 2048 {
		return zero, errors.New("oversized IPC response")
	}
	if err := json.Unmarshal(response, &zero); err != nil {
		return reply{}, err
	}
	return zero, nil
}

func TestLinuxSocketOwnerModesAndPeerIdentity(t *testing.T) {
	harness := newLinuxHarness(t, 0700, 0600)
	directoryInfo, err := os.Stat(filepath.Dir(harness.endpoint.path))
	if err != nil {
		t.Fatal("could not stat isolated socket directory")
	}
	socketInfo, err := os.Lstat(harness.endpoint.path)
	if err != nil {
		t.Fatal("could not stat isolated socket")
	}
	if directoryInfo.Mode().Perm() != 0700 || socketInfo.Mode().Perm() != 0600 {
		t.Fatal("Unix socket parent or endpoint mode was broader than expected")
	}
	stat, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		t.Fatal("Unix socket owner was not the creating account")
	}

	digest := syntheticValueDigest(harness.broker.values[testReference])
	result := runHelper(t, "native", map[string]string{
		"KREDOXI_IPC_ENDPOINT":        harness.endpoint.path,
		"KREDOXI_IPC_EXPECTED_DIGEST": digest,
	}, nil)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:native=resolved") {
		t.Fatal("separate same-account process did not resolve the synthetic value")
	}
	assertOutputDoesNotContain(t, result.stdout+result.stderr, []byte(harness.broker.values[testReference]))
	select {
	case observed := <-harness.evidence:
		if observed.status != "resolved" || observed.peer.uid != uint32(os.Getuid()) ||
			observed.peer.gid != uint32(os.Getgid()) || observed.peer.pid == int32(os.Getpid()) {
			t.Fatal("kernel peer credentials did not identify the separate same-account process")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not record kernel peer credentials")
	}
	if got := harness.broker.lookups.Load(); got != 1 {
		t.Fatal("authorized synthetic request did not perform exactly one provider lookup")
	}
}

func TestLinuxPolicyDenialPrecedesLookup(t *testing.T) {
	harness := newLinuxHarness(t, 0700, 0600)
	got, err := linuxRequest(harness.endpoint.path, []byte(`{"reference":"kredoxi://v1/demo/other/password","claimed_principal":"uid:`+strconv.Itoa(os.Getuid())+`","claimed_uid":0,"claimed_pid":1}`))
	if err != nil || got.Status != "policy_denied" || got.Value != "" {
		t.Fatal("unauthorized exact reference was not denied")
	}
	if got := harness.broker.lookups.Load(); got != 0 {
		t.Fatal("policy denial reached the provider")
	}
	missing := "kredoxi://v1/demo/example/missing"
	harness.broker.allowed["uid:"+strconv.Itoa(os.Getuid())][missing] = true
	got, err = linuxRequest(harness.endpoint.path, []byte(`{"reference":"`+missing+`"}`))
	if err != nil || got.Status != "secret_not_found" || got.Value != "" {
		t.Fatal("authorized missing reference did not retain the missing-secret result")
	}
	if got := harness.broker.lookups.Load(); got != 1 {
		t.Fatal("authorized missing reference did not perform exactly one provider lookup")
	}
	select {
	case observed := <-harness.evidence:
		if observed.status != "policy_denied" || observed.peer.uid != uint32(os.Getuid()) {
			t.Fatal("spoofed client fields changed the kernel-derived identity")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not record the denied request")
	}
}

func TestLinuxEndpointPrecreationAndStalePathFailClosed(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "existing")
	if err := os.WriteFile(path, []byte("synthetic-endpoint-marker"), 0600); err != nil {
		t.Fatal("could not create endpoint precreation fixture")
	}
	if _, err := listenLinuxEndpoint(path, 0600); err == nil {
		t.Fatal("pre-created endpoint path was replaced")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "synthetic-endpoint-marker" {
		t.Fatal("pre-created endpoint was modified")
	}

	stalePath := filepath.Join(directory, "stale.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: stalePath, Net: "unix"})
	if err != nil {
		t.Fatal("could not create stale-socket fixture")
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal("could not close stale-socket fixture")
	}
	if _, err := listenLinuxEndpoint(stalePath, 0600); err == nil {
		t.Fatal("stale socket path was silently reused")
	}
	if _, err := os.Lstat(stalePath); err != nil {
		t.Fatal("stale socket path was removed during failed startup")
	}
}

func TestLinuxSameAccountCanReplacePathnameEndpoint(t *testing.T) {
	harness := newLinuxHarness(t, 0700, 0600)
	original := harness.endpoint.path
	held := original + ".held"
	if err := os.Rename(original, held); err != nil {
		t.Fatal("same-account endpoint replacement setup failed")
	}
	attacker, err := listenLinuxEndpoint(original, 0600)
	if err != nil {
		t.Fatal("same-account actor could not bind the substituted endpoint")
	}
	t.Cleanup(func() {
		if err := attacker.close(); err != nil {
			t.Error("could not close substituted endpoint")
		}
	})
	accepted := make(chan struct{}, 1)
	go func() {
		connection, err := attacker.listener.AcceptUnix()
		if err == nil {
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()
	connection, err := net.DialTimeout("unix", original, time.Second)
	if err != nil {
		t.Fatal("client could not connect through substituted endpoint path")
	}
	_ = connection.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("substituted endpoint did not receive the connection")
	}
	if err := harness.endpoint.close(); err != nil {
		t.Fatal("original endpoint did not preserve the replacement path")
	}
	if _, err := os.Lstat(original); err != nil {
		t.Fatal("original endpoint cleanup removed the substituted path")
	}
}

func TestLinuxConcurrentClientsAndBrokerShutdown(t *testing.T) {
	harness := newLinuxHarness(t, 0700, 0600)
	const clients = 12
	var wait sync.WaitGroup
	failures := make(chan error, clients)
	authorized := 0
	for index := range clients {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			reference, expected := testReference, "resolved"
			if index%2 != 0 {
				reference, expected = "kredoxi://v1/demo/other/password", "policy_denied"
			}
			requestBytes := []byte(`{"reference":"` + reference + `"}`)
			result, err := linuxRequest(harness.endpoint.path, requestBytes)
			if err != nil {
				failures <- err
			} else if result.Status != expected {
				failures <- errors.New("concurrent request had an unexpected authorization result")
			}
		}(index)
		if index%2 == 0 {
			authorized++
		}
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal("concurrent Unix socket client failed")
		}
	}
	if got := harness.broker.lookups.Load(); got != uint32(authorized) {
		t.Fatal("concurrent authorized requests did not reach provider exactly once each")
	}
	if err := harness.endpoint.close(); err != nil {
		t.Fatal("Unix socket broker shutdown failed")
	}
	select {
	case <-harness.done:
	case <-time.After(2 * time.Second):
		t.Fatal("Unix socket broker did not terminate after listener close")
	}
}

func TestLinuxClientDisconnectDoesNotResolve(t *testing.T) {
	harness := newLinuxHarness(t, 0700, 0600)
	connection, err := net.DialTimeout("unix", harness.endpoint.path, time.Second)
	if err != nil {
		t.Fatal("could not connect the incomplete-request client")
	}
	if _, err := connection.Write([]byte(`{"reference":"` + testReference)); err != nil {
		_ = connection.Close()
		t.Fatal("could not send the incomplete synthetic request")
	}
	if err := connection.Close(); err != nil {
		t.Fatal("could not terminate the incomplete-request client")
	}
	select {
	case observed := <-harness.evidence:
		if observed.status != "invalid_request" {
			t.Fatal("disconnected client did not fail as an invalid request")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not observe the disconnected client")
	}
	got, err := linuxRequest(harness.endpoint.path, []byte(`{"reference":"`+testReference+`"}`))
	if err != nil || got.Status != "resolved" {
		t.Fatal("broker did not continue after a client disconnect")
	}
	if lookups := harness.broker.lookups.Load(); lookups != 1 {
		t.Fatal("disconnected request reached the provider")
	}
}

func TestLinuxDifferentUIDBlockedBySocketMode(t *testing.T) {
	sudo, _ := availableNobodyUID(t)
	harness := newLinuxHarness(t, 0711, 0600)
	result := runHelperAsNobody(t, sudo, "native", map[string]string{
		"KREDOXI_IPC_ENDPOINT":        harness.endpoint.path,
		"KREDOXI_IPC_EXPECTED_STATUS": "connect_denied",
	}, nil)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:native=connect_denied") {
		t.Fatal("different UID was not blocked by the socket's owner-only mode")
	}
	if got := harness.broker.lookups.Load(); got != 0 {
		t.Fatal("socket permission denial reached the provider")
	}
	select {
	case <-harness.evidence:
		t.Fatal("different UID reached the broker despite socket mode 0600")
	default:
	}
}

func TestLinuxDifferentUIDCannotReplaceBrokerEndpoint(t *testing.T) {
	sudo, otherUID := availableNobodyUID(t)
	harness := newLinuxHarness(t, 0700, 0666)
	directoryInfo, err := os.Stat(filepath.Dir(harness.endpoint.path))
	if err != nil {
		t.Fatal("could not inspect broker endpoint directory")
	}
	directoryStat, ok := directoryInfo.Sys().(*syscall.Stat_t)
	if !ok || directoryInfo.Mode().Perm() != 0700 || directoryStat.Uid != uint32(os.Getuid()) {
		t.Fatal("broker endpoint directory was not private and owned by the broker account")
	}
	socketInfo, err := os.Lstat(harness.endpoint.path)
	if err != nil || socketInfo.Mode().Perm() != 0666 {
		t.Fatal("test endpoint did not have the expected deliberately broad socket mode")
	}

	for _, operation := range []string{"rename_endpoint", "unlink_endpoint"} {
		result := runHelperAsNobody(t, sudo, "native", map[string]string{
			"KREDOXI_IPC_ENDPOINT":       harness.endpoint.path,
			"KREDOXI_IPC_TEST_OPERATION": operation,
			"KREDOXI_IPC_EXPECTED_UID":   strconv.FormatUint(uint64(otherUID), 10),
			"KREDOXI_IPC_RENAME_TARGET":  harness.endpoint.path + ".substituted",
		}, nil)
		if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:native=endpoint_operation_denied") {
			t.Fatal("different UID was not denied endpoint replacement by the broker-owned directory")
		}
	}
	current, err := os.Lstat(harness.endpoint.path)
	if err != nil || !os.SameFile(socketInfo, current) {
		t.Fatal("unrelated UID changed the broker endpoint")
	}
}

func TestLinuxDistinctUIDDeniedByKernelAndPolicy(t *testing.T) {
	sudo, otherUID := availableNobodyUID(t)
	harness := newLinuxHarness(t, 0711, 0666)
	result := runHelperAsNobody(t, sudo, "native", map[string]string{
		"KREDOXI_IPC_ENDPOINT":        harness.endpoint.path,
		"KREDOXI_IPC_EXPECTED_STATUS": "policy_denied",
	}, nil)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:native=policy_denied") {
		t.Fatal("distinct existing UID was not denied by exact principal policy")
	}
	select {
	case observed := <-harness.evidence:
		if observed.peer.uid != otherUID || observed.status != "policy_denied" {
			t.Fatal("SO_PEERCRED did not report the distinct UID or policy denial")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("broker did not observe the distinct UID request")
	}
	if got := harness.broker.lookups.Load(); got != 0 {
		t.Fatal("distinct UID denial reached the provider")
	}
}

func TestLinuxClientAcceptsSyntheticFakeBroker(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "fake-broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal("could not create synthetic fake-broker endpoint")
	}
	defer listener.Close()

	value, err := randomSyntheticValue()
	if err != nil {
		t.Fatal("could not create a synthetic fake-broker response")
	}
	type observation struct {
		peer    linuxPeer
		request request
		raw     []byte
		err     error
	}
	observed := make(chan observation, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			observed <- observation{err: acceptErr}
			return
		}
		defer connection.Close()
		peer, peerErr := linuxPeerCredentials(connection)
		raw, readErr := io.ReadAll(io.LimitReader(connection, maxRequestBytes+1))
		input, parseErr := parseRequest(raw)
		result := observation{peer: peer, request: input, raw: raw, err: errors.Join(peerErr, readErr, parseErr)}
		if result.err == nil && len(raw) <= maxRequestBytes {
			result.err = json.NewEncoder(connection).Encode(reply{Status: "resolved", Value: value})
		}
		observed <- result
	}()

	result := runHelper(t, "native", map[string]string{
		"KREDOXI_IPC_ENDPOINT":        path,
		"KREDOXI_IPC_EXPECTED_DIGEST": syntheticValueDigest(value),
	}, nil)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:native=resolved") {
		t.Fatal("client did not accept the fake endpoint's synthetic response")
	}
	select {
	case evidence := <-observed:
		if evidence.err != nil || evidence.peer.uid != uint32(os.Getuid()) ||
			evidence.request.Reference != testReference ||
			evidence.request.ClaimedPrincipal != "uid:0" ||
			evidence.request.ClaimedUID != 0 || evidence.request.ClaimedPID != 1 {
			t.Fatal("fake endpoint did not observe the expected request and kernel peer identity")
		}
		if bytes.Contains(evidence.raw, []byte(value)) ||
			bytes.Contains(evidence.raw, []byte("private_key")) {
			t.Fatal("client request exposed synthetic response or private-key material")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake endpoint did not receive the client request")
	}
	assertOutputDoesNotContain(t, result.stdout+result.stderr, []byte(value))
}

func TestLinuxCopiedSyntheticMTLSKeyWorksFromDifferentUID(t *testing.T) {
	sudo, _ := availableNobodyUID(t)
	value, err := randomSyntheticValue()
	if err != nil {
		t.Fatal("could not create synthetic mTLS test value")
	}
	pki, broker, telemetry := startMTLSBaseline(t, value)
	material, err := pki.ClientMaterial("urn:kredoxi:principal:demo-consumer")
	if err != nil {
		t.Fatal("could not create synthetic client key")
	}
	input, err := json.Marshal(struct {
		Material  synthetic.TLSMaterial `json:"material"`
		Reference string                `json:"reference"`
	}{Material: material, Reference: testReference})
	if err != nil {
		t.Fatal("could not encode in-memory test material")
	}
	result := runHelperAsNobody(t, sudo, "mtls", map[string]string{
		"KREDOXI_IPC_ADDRESS": broker.Address(),
	}, input)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:mtls=resolved") {
		t.Fatal("a different-UID process could not use the copied synthetic mTLS key")
	}
	assertOutputDoesNotContain(t, result.stdout+result.stderr, material.PrivateKey)
	assertOutputDoesNotContain(t, result.stdout+result.stderr, []byte(value))
	assertOutputDoesNotContain(t, telemetry.String(), material.PrivateKey)
	assertOutputDoesNotContain(t, telemetry.String(), []byte(value))
}

func availableNobodyUID(t *testing.T) (string, uint32) {
	t.Helper()
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		t.Skip("blocked: no sudo executable for an existing distinct account")
	}
	probe := exec.Command(sudo, "-n", "-u", "nobody", "--", "id", "-u")
	probeOutput, err := probe.Output()
	if err != nil {
		t.Skip("blocked: runner cannot execute as the existing nobody account without prompting")
	}
	otherUID, err := strconv.ParseUint(strings.TrimSpace(string(probeOutput)), 10, 32)
	if err != nil || uint32(otherUID) == uint32(os.Getuid()) {
		t.Skip("blocked: no distinct existing UID is available")
	}
	return sudo, uint32(otherUID)
}

func runHelperAsNobody(t *testing.T, sudo, mode string, extraEnv map[string]string, stdin []byte) helperResult {
	t.Helper()
	directory, err := os.MkdirTemp("", "kredoxi-ipc-helper-")
	if err != nil {
		t.Fatal("could not create a temporary helper directory")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error("could not remove the temporary helper directory")
		}
	})
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal("could not make the helper directory traversable")
	}
	binaryPath := filepath.Join(directory, "ipc-test")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal("could not open the experiment test binary")
	}
	target, err := os.OpenFile(binaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		_ = source.Close()
		t.Fatal("could not create the temporary experiment helper")
	}
	_, copyErr := io.Copy(target, source)
	sourceErr := source.Close()
	targetErr := target.Close()
	if copyErr != nil || sourceErr != nil || targetErr != nil {
		t.Fatal("could not stage the temporary experiment helper")
	}
	if err := os.Chmod(binaryPath, 0755); err != nil {
		t.Fatal("could not mark the temporary experiment helper executable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := []string{"-n", "-u", "nobody", "--", "env", "KREDOXI_IPC_EXPERIMENT_HELPER=" + mode}
	for name, value := range extraEnv {
		args = append(args, name+"="+value)
	}
	args = append(args, binaryPath, "-test.run=^TestIPCProcessHelper$")
	cmd := exec.CommandContext(ctx, sudo, args...)
	cmd.Env = helperEnvironment("", nil)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = errors.New("distinct-UID helper exceeded its 10-second bound")
	}
	return helperResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}
