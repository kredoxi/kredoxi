//go:build windows

package ipc

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const (
	pipeAccessDuplex       = 0x00000003
	pipeTypeByte           = 0x00000000
	pipeReadModeByte       = 0x00000000
	pipeWait               = 0x00000000
	pipeRejectRemoteClient = 0x00000008
	fileFlagFirstPipe      = 0x00080000
	securitySQOSPresent    = 0x00100000
	securityImpersonation  = 0x00020000
	tokenQuery             = 0x0008
	errorIOPending         = syscall.Errno(997)
	errorPipeConnected     = syscall.Errno(535)
	errorNoToken           = syscall.Errno(1008)
	errorOperationAborted  = syscall.Errno(995)
	errorIOIncomplete      = syscall.Errno(996)
	errorNotFound          = syscall.Errno(1168)
	waitTimeout            = 258
	waitFailed             = 0xffffffff
	pipeTimeoutMillis      = 3000
)

var errPipeOperationTimeout = errors.New("named-pipe operation timed out")

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	procCreateNamedPipeW      = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe      = kernel32.NewProc("ConnectNamedPipe")
	procCreateEventW          = kernel32.NewProc("CreateEventW")
	procWaitForSingleObject   = kernel32.NewProc("WaitForSingleObject")
	procGetOverlappedResult   = kernel32.NewProc("GetOverlappedResult")
	procCancelIoEx            = kernel32.NewProc("CancelIoEx")
	procGetHandleInformation  = kernel32.NewProc("GetHandleInformation")
	procWaitNamedPipeW        = kernel32.NewProc("WaitNamedPipeW")
	procConvertStringSDDL     = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procImpersonatePipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")
	procRevertToSelf          = advapi32.NewProc("RevertToSelf")
	procOpenThreadToken       = advapi32.NewProc("OpenThreadToken")
	procLocalFree             = kernel32.NewProc("LocalFree")
)

type windowsEvidence struct {
	sid    string
	status string
}

type windowsHarness struct {
	name      string
	handle    syscall.Handle
	broker    *experimentBroker
	brokerSID string
	evidence  chan windowsEvidence
	connected chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func runNativeIPCHelper(t *testing.T) {
	t.Helper()
	name := os.Getenv("KREDOXI_IPC_ENDPOINT")
	reference := os.Getenv("KREDOXI_IPC_REFERENCE")
	if reference == "" {
		reference = testReference
	}
	requestBytes, err := json.Marshal(request{
		Reference: reference, ClaimedPrincipal: "sid:S-1-5-18",
		ClaimedUID: 0, ClaimedPID: 1,
	})
	if err != nil {
		t.Fatal("could not encode synthetic IPC request")
	}
	got, err := windowsRequest(name, requestBytes)
	if err != nil {
		t.Fatal("native named-pipe request failed")
	}
	want := os.Getenv("KREDOXI_IPC_EXPECTED_STATUS")
	if want == "" {
		want = "resolved"
	}
	if got.Status != want {
		t.Fatal("native named pipe returned an unexpected decision")
	}
	if want == "resolved" {
		wantDigest := os.Getenv("KREDOXI_IPC_EXPECTED_DIGEST")
		if wantDigest == "" || syntheticValueDigest(got.Value) != wantDigest {
			t.Fatal("native named pipe returned an unexpected synthetic value")
		}
	}
	if _, err := fmt.Fprintf(os.Stdout, "ipc-helper:native=%s\n", want); err != nil {
		t.Fatal("could not report native IPC result")
	}
}

func newWindowsHarness(t *testing.T) *windowsHarness {
	t.Helper()
	name, err := newPipeName()
	if err != nil {
		t.Fatal("could not create synthetic pipe name")
	}
	brokerSID, err := currentUserSID()
	if err != nil {
		t.Fatal("could not read broker process token SID")
	}
	value, err := randomSyntheticValue()
	if err != nil {
		t.Fatal("could not generate synthetic IPC value")
	}
	return startWindowsHarness(t, name, brokerSID, value)
}

func startWindowsHarness(t *testing.T, name, brokerSID, value string) *windowsHarness {
	t.Helper()
	handle, err := createPipe(name, brokerSID, true)
	if err != nil {
		t.Fatal("could not create named pipe with explicit DACL")
	}
	harness := &windowsHarness{
		name: name, handle: handle, brokerSID: brokerSID,
		broker:    newExperimentBroker("sid:"+brokerSID, testReference, value),
		evidence:  make(chan windowsEvidence, 16),
		connected: make(chan struct{}),
		done:      make(chan struct{}),
	}
	t.Cleanup(func() {
		if err := harness.close(); err != nil {
			t.Error("could not close named pipe")
		}
		select {
		case <-harness.done:
		case <-time.After(4 * time.Second):
			t.Error("named pipe server did not stop")
		}
	})
	go harness.serve()
	return harness
}

func (h *windowsHarness) serve() {
	defer close(h.done)
	if err := connectPipe(h.handle, pipeTimeoutMillis); err != nil {
		return
	}
	close(h.connected)
	data, err := readFrame(h.handle, true)
	if err != nil {
		result := reply{Status: "invalid_request"}
		h.evidence <- windowsEvidence{status: result.Status}
		_ = writeFrame(h.handle, result, true)
		return
	}
	sid, err := impersonatedClientSID(h.handle)
	result := reply{Status: "authentication_denied"}
	if err == nil {
		result = h.broker.resolve("sid:"+sid, data)
	}
	h.evidence <- windowsEvidence{sid: sid, status: result.Status}
	_ = writeFrame(h.handle, result, true)
}

func (h *windowsHarness) close() error {
	h.closeOnce.Do(func() {
		_, _, _ = procCancelIoEx.Call(uintptr(h.handle), 0)
		h.closeErr = syscall.CloseHandle(h.handle)
	})
	return h.closeErr
}

func (h *windowsHarness) processRequest(handle syscall.Handle, data []byte) reply {
	sid, err := impersonatedClientSID(handle)
	if err != nil {
		return reply{Status: "authentication_denied"}
	}
	return h.broker.resolve("sid:"+sid, data)
}

func newPipeName() (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return `\\.\pipe\kredoxi-ipc-` + hex.EncodeToString(random), nil
}

func createPipe(name, sid string, first bool) (syscall.Handle, error) {
	sddl, err := syscall.UTF16PtrFromString("D:P(A;;GA;;;" + sid + ")")
	if err != nil {
		return syscall.InvalidHandle, err
	}
	var descriptor uintptr
	result, _, callErr := procConvertStringSDDL.Call(
		uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0,
	)
	if result == 0 {
		return syscall.InvalidHandle, callErr
	}
	defer procLocalFree.Call(descriptor)

	attributes := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
		InheritHandle:      0,
	}
	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	openMode := uintptr(pipeAccessDuplex | syscall.FILE_FLAG_OVERLAPPED)
	if first {
		openMode |= fileFlagFirstPipe
	}
	pipeMode := uintptr(pipeTypeByte | pipeReadModeByte | pipeWait | pipeRejectRemoteClient)
	handle, _, callErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(namePointer)), openMode, pipeMode, 1,
		maxRequestBytes+2, maxRequestBytes+2, pipeTimeoutMillis,
		uintptr(unsafe.Pointer(&attributes)),
	)
	if handle == uintptr(syscall.InvalidHandle) {
		return syscall.InvalidHandle, callErr
	}
	return syscall.Handle(handle), nil
}

func connectPipe(handle syscall.Handle, timeout uint32) error {
	event, err := createPipeEvent()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(event)
	overlapped := syscall.Overlapped{HEvent: event}
	connected, _, callErr := procConnectNamedPipe.Call(
		uintptr(handle), uintptr(unsafe.Pointer(&overlapped)),
	)
	if connected != 0 {
		return nil
	}
	if errors.Is(callErr, errorPipeConnected) {
		return nil
	}
	if !errors.Is(callErr, errorIOPending) {
		return callErr
	}
	_, err = waitOverlapped(handle, &overlapped, timeout)
	runtime.KeepAlive(&overlapped)
	return err
}

func createPipeEvent() (syscall.Handle, error) {
	event, _, err := procCreateEventW.Call(0, 1, 0, 0)
	if event == 0 {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(event), nil
}

func waitOverlapped(handle syscall.Handle, overlapped *syscall.Overlapped, timeout uint32) (uint32, error) {
	waitResult, _, waitErr := procWaitForSingleObject.Call(uintptr(overlapped.HEvent), uintptr(timeout))
	if waitResult == waitTimeout {
		cancelErr := cancelOverlapped(handle, overlapped)
		transferred, completionErr := awaitOverlappedCompletion(handle, overlapped)
		return transferred, errors.Join(
			errPipeOperationTimeout,
			nonCancellationError(cancelErr),
			nonCancellationError(completionErr),
		)
	}
	if waitResult == waitFailed {
		if waitErr == nil {
			waitErr = errors.New("WaitForSingleObject failed without an error code")
		}
		cancelErr := cancelOverlapped(handle, overlapped)
		transferred, completionErr := awaitOverlappedCompletion(handle, overlapped)
		return transferred, errors.Join(
			fmt.Errorf("wait for named-pipe operation: %w", waitErr),
			nonCancellationError(cancelErr),
			nonCancellationError(completionErr),
		)
	}
	if waitResult != 0 {
		cancelErr := cancelOverlapped(handle, overlapped)
		transferred, completionErr := awaitOverlappedCompletion(handle, overlapped)
		return transferred, errors.Join(
			fmt.Errorf("unexpected named-pipe wait result: %d", waitResult),
			nonCancellationError(cancelErr),
			nonCancellationError(completionErr),
		)
	}
	return overlappedResult(handle, overlapped, false)
}

func cancelOverlapped(handle syscall.Handle, overlapped *syscall.Overlapped) error {
	cancelled, _, err := procCancelIoEx.Call(
		uintptr(handle), uintptr(unsafe.Pointer(overlapped)),
	)
	if cancelled == 0 && !errors.Is(err, errorNotFound) {
		return fmt.Errorf("cancel named-pipe operation: %w", err)
	}
	return nil
}

func awaitOverlappedCompletion(handle syscall.Handle, overlapped *syscall.Overlapped) (uint32, error) {
	for {
		transferred, err := overlappedResult(handle, overlapped, true)
		if !errors.Is(err, errorIOIncomplete) {
			return transferred, err
		}
		_, _, _ = procWaitForSingleObject.Call(uintptr(overlapped.HEvent), ^uintptr(0))
	}
}

func overlappedResult(handle syscall.Handle, overlapped *syscall.Overlapped, wait bool) (uint32, error) {
	var transferred uint32
	waitFlag := uintptr(0)
	if wait {
		waitFlag = 1
	}
	ok, _, err := procGetOverlappedResult.Call(
		uintptr(handle), uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(&transferred)), waitFlag,
	)
	if ok == 0 {
		return transferred, err
	}
	return transferred, nil
}

func nonCancellationError(err error) error {
	if errors.Is(err, errorOperationAborted) {
		return nil
	}
	return err
}

func pipeIO(handle syscall.Handle, data []byte, write, overlapped bool) (int, error) {
	return pipeIOWithTimeout(handle, data, write, overlapped, pipeTimeoutMillis)
}

func pipeIOWithTimeout(handle syscall.Handle, data []byte, write, overlapped bool, timeout uint32) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if !overlapped {
		var transferred uint32
		var err error
		if write {
			err = syscall.WriteFile(handle, data, &transferred, nil)
		} else {
			err = syscall.ReadFile(handle, data, &transferred, nil)
		}
		if err != nil {
			return int(transferred), err
		}
		return int(transferred), nil
	}

	event, err := createPipeEvent()
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(event)
	operation := syscall.Overlapped{HEvent: event}
	var transferred uint32
	if write {
		err = syscall.WriteFile(handle, data, &transferred, &operation)
	} else {
		err = syscall.ReadFile(handle, data, &transferred, &operation)
	}
	if err != nil && !errors.Is(err, errorIOPending) {
		return int(transferred), err
	}
	if errors.Is(err, errorIOPending) {
		transferred, err = waitOverlapped(handle, &operation, timeout)
		runtime.KeepAlive(&operation)
		runtime.KeepAlive(data)
		if err != nil {
			return 0, err
		}
	}
	if transferred == 0 {
		return 0, io.EOF
	}
	return int(transferred), nil
}

func readFrame(handle syscall.Handle, overlapped bool) ([]byte, error) {
	var lengthBytes [2]byte
	if err := readExactPipe(handle, lengthBytes[:], overlapped); err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint16(lengthBytes[:]))
	if length < 1 || length > maxRequestBytes {
		return nil, errors.New("invalid request frame size")
	}
	data := make([]byte, length)
	if err := readExactPipe(handle, data, overlapped); err != nil {
		return nil, err
	}
	return data, nil
}

func writeFrame(handle syscall.Handle, value any, overlapped bool) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > maxRequestBytes {
		return errors.New("invalid response frame")
	}
	frame := make([]byte, 2)
	binary.LittleEndian.PutUint16(frame, uint16(len(data)))
	if len(data) <= maxRequestBytes {
		frame = append(frame, data...)
	}
	return writeExactPipe(handle, frame, overlapped)
}

func readExactPipe(handle syscall.Handle, data []byte, overlapped bool) error {
	for len(data) > 0 {
		n, err := pipeIO(handle, data, false, overlapped)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func writeExactPipe(handle syscall.Handle, data []byte, overlapped bool) error {
	for len(data) > 0 {
		n, err := pipeIO(handle, data, true, overlapped)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func windowsRequest(name string, data []byte) (reply, error) {
	var zero reply
	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return zero, err
	}
	waited, _, waitErr := procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(namePointer)), pipeTimeoutMillis)
	if waited == 0 {
		return zero, waitErr
	}
	handle, err := syscall.CreateFile(
		namePointer,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|securitySQOSPresent|securityImpersonation, 0,
	)
	if err != nil {
		return zero, err
	}
	defer syscall.CloseHandle(handle)
	if len(data) > 65535 {
		return zero, errors.New("oversized request frame")
	}
	frame := make([]byte, 2)
	binary.LittleEndian.PutUint16(frame, uint16(len(data)))
	if len(data) <= maxRequestBytes {
		frame = append(frame, data...)
	}
	if err := writeExactPipe(handle, frame, false); err != nil {
		return zero, err
	}
	responseData, err := readFrame(handle, false)
	if err != nil {
		return zero, err
	}
	if err := json.Unmarshal(responseData, &zero); err != nil {
		return reply{}, err
	}
	return zero, nil
}

func currentUserSID() (string, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return "", err
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, tokenQuery, &token); err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String()
}

func threadUserSID() (string, error) {
	var token syscall.Token
	thread := syscall.Handle(^uintptr(1))
	opened, _, openErr := procOpenThreadToken.Call(
		uintptr(thread), tokenQuery, 1, uintptr(unsafe.Pointer(&token)),
	)
	if opened == 0 {
		return "", openErr
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String()
}

func impersonatedClientSID(pipe syscall.Handle) (string, error) {
	runtime.LockOSThread()
	impersonated, _, impersonateErr := procImpersonatePipeClient.Call(uintptr(pipe))
	if impersonated == 0 {
		runtime.UnlockOSThread()
		return "", impersonateErr
	}

	sid, tokenErr := threadUserSID()
	reverted, _, _ := procRevertToSelf.Call()
	if reverted == 0 {
		// Do not return to broker logic or unlock an OS thread with a client token.
		runtime.Goexit()
	}
	restoreErr := verifyRestoredContextBeforeUnlock(verifyBrokerThreadContext, runtime.UnlockOSThread)
	if restoreErr != nil {
		runtime.Goexit()
	}
	if tokenErr != nil {
		return "", tokenErr
	}
	return sid, nil
}

func verifyBrokerThreadContext() error {
	if _, err := threadUserSID(); !errors.Is(err, errorNoToken) {
		return errors.New("broker thread token remained after RevertToSelf")
	}
	return nil
}

func verifyRestoredContextBeforeUnlock(verify func() error, unlock func()) error {
	err := verify()
	if err == nil {
		unlock()
	}
	return err
}

func getHandleFlags(handle syscall.Handle) (uint32, error) {
	var flags uint32
	result, _, err := procGetHandleInformation.Call(
		uintptr(handle), uintptr(unsafe.Pointer(&flags)),
	)
	if result == 0 {
		return 0, err
	}
	return flags, nil
}

func duplicateHandle(handle syscall.Handle) (syscall.Handle, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return syscall.InvalidHandle, err
	}
	var duplicate syscall.Handle
	if err := syscall.DuplicateHandle(
		process, handle, process, &duplicate, 0, false, syscall.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return syscall.InvalidHandle, err
	}
	return duplicate, nil
}

func TestWindowsOverlappedReadTimeoutWaitsForCancellation(t *testing.T) {
	name, err := newPipeName()
	if err != nil {
		t.Fatal("could not create timeout-test pipe name")
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal("could not read broker token SID")
	}
	server, err := createPipe(name, sid, true)
	if err != nil {
		t.Fatal("could not create timeout-test pipe")
	}
	defer syscall.CloseHandle(server)

	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal("could not encode timeout-test pipe name")
	}
	waited, _, waitErr := procWaitNamedPipeW.Call(
		uintptr(unsafe.Pointer(namePointer)), pipeTimeoutMillis,
	)
	if waited == 0 {
		t.Fatalf("timeout-test pipe was not ready: %v", waitErr)
	}
	client, err := syscall.CreateFile(
		namePointer,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|securitySQOSPresent|securityImpersonation,
		0,
	)
	if err != nil {
		t.Fatal("could not connect timeout-test client")
	}
	defer syscall.CloseHandle(client)
	if err := connectPipe(server, pipeTimeoutMillis); err != nil {
		t.Fatal("could not accept timeout-test client")
	}

	buffer := make([]byte, 1)
	if count, err := pipeIOWithTimeout(server, buffer, false, true, 10); count != 0 ||
		!errors.Is(err, errPipeOperationTimeout) {
		t.Fatalf("pending read did not return a confirmed timeout: count=%d, err=%v", count, err)
	}
	var written uint32
	if err := syscall.WriteFile(client, []byte{1}, &written, nil); err != nil {
		t.Fatal("client could not write after the pending server read was canceled")
	}
	if written != 1 {
		t.Fatal("client write after cancellation was incomplete")
	}
}

func TestWindowsRestorationIsVerifiedBeforeThreadUnlock(t *testing.T) {
	unlocked := false
	err := verifyRestoredContextBeforeUnlock(
		func() error {
			if unlocked {
				return errors.New("thread was unlocked before restoration verification")
			}
			return nil
		},
		func() { unlocked = true },
	)
	if err != nil || !unlocked {
		t.Fatal("successful restoration was not verified before unlocking the thread")
	}

	unlocked = false
	err = verifyRestoredContextBeforeUnlock(
		func() error { return errors.New("restoration verification failed") },
		func() { unlocked = true },
	)
	if err == nil || unlocked {
		t.Fatal("failed restoration verification unlocked the thread")
	}
}

func TestWindowsPipeDACLAndSameAccountPeerIdentity(t *testing.T) {
	harness := newWindowsHarness(t)
	flags, err := getHandleFlags(harness.handle)
	if err != nil || flags&syscall.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("named-pipe server handle was inheritable")
	}
	if pipeRejectRemoteClient == 0 {
		t.Fatal("named pipe did not request remote-client rejection")
	}
	digest := syntheticValueDigest(harness.broker.values[testReference])
	result := runHelper(t, "native", map[string]string{
		"KREDOXI_IPC_ENDPOINT":        harness.name,
		"KREDOXI_IPC_EXPECTED_DIGEST": digest,
	}, nil)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:native=resolved") {
		t.Fatal("separate same-account process did not resolve the synthetic value")
	}
	assertOutputDoesNotContain(t, result.stdout+result.stderr, []byte(harness.broker.values[testReference]))
	select {
	case observed := <-harness.evidence:
		if observed.status != "resolved" || observed.sid != harness.brokerSID {
			t.Fatal("impersonated client token did not identify the same-account helper")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("broker did not observe impersonated pipe-client SID")
	}
	if _, err := threadUserSID(); !errors.Is(err, errorNoToken) {
		t.Fatal("broker thread retained client impersonation after request")
	}
	if got, err := currentUserSID(); err != nil || got != harness.brokerSID {
		t.Fatal("broker process token changed after client impersonation")
	}
	if got := harness.broker.lookups.Load(); got != 1 {
		t.Fatal("authorized synthetic request did not perform exactly one provider lookup")
	}
}

func TestWindowsImpersonationFailureFailsClosed(t *testing.T) {
	harness := newWindowsHarness(t)
	before, err := currentUserSID()
	if err != nil {
		t.Fatal("could not read broker token before failure test")
	}
	result := harness.processRequest(syscall.InvalidHandle, []byte(`{"reference":"`+testReference+`"}`))
	if result.Status != "authentication_denied" || result.Value != "" {
		t.Fatal("impersonation failure did not fail closed")
	}
	after, err := currentUserSID()
	if err != nil || before != after {
		t.Fatal("broker process token changed after impersonation failure")
	}
	if _, err := threadUserSID(); !errors.Is(err, errorNoToken) {
		t.Fatal("failed impersonation left a thread token")
	}
	if got := harness.broker.lookups.Load(); got != 0 {
		t.Fatal("impersonation failure reached the provider")
	}
}

func TestWindowsExactPolicyAndMalformedRequest(t *testing.T) {
	harness := newWindowsHarness(t)
	got, err := windowsRequest(harness.name, []byte(`{"reference":"kredoxi://v1/demo/other/password","claimed_principal":"sid:S-1-5-18","claimed_uid":0,"claimed_pid":1}`))
	if err != nil || got.Status != "policy_denied" || got.Value != "" {
		t.Fatal("spoofed identity or unauthorized reference was accepted")
	}

	harness = newWindowsHarness(t)
	missing := "kredoxi://v1/demo/example/missing"
	harness.broker.allowed["sid:"+harness.brokerSID][missing] = true
	got, err = windowsRequest(harness.name, []byte(`{"reference":"`+missing+`"}`))
	if err != nil || got.Status != "secret_not_found" || got.Value != "" {
		t.Fatal("authorized missing reference did not retain the missing-secret result")
	}
	if got := harness.broker.lookups.Load(); got != 1 {
		t.Fatal("authorized missing reference did not perform exactly one provider lookup")
	}
	for _, raw := range []string{
		"", `{"reference":"` + testReference + `","reference":"` + testReference + `"}`,
		`{"Reference":"` + testReference + `"}`, strings.Repeat("x", maxRequestBytes+1),
	} {
		server := newWindowsHarness(t)
		response, err := windowsRequest(server.name, []byte(raw))
		if err != nil || response.Status != "invalid_request" {
			t.Fatal("malformed named-pipe request was not rejected")
		}
	}
	if got := harness.broker.lookups.Load(); got != 1 {
		t.Fatal("unauthorized or malformed named-pipe request reached the provider")
	}
}

func TestWindowsPipeFirstInstanceAndNameReuse(t *testing.T) {
	name, err := newPipeName()
	if err != nil {
		t.Fatal("could not create synthetic pipe name")
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal("could not read broker token SID")
	}
	precreated, err := createPipe(name, sid, false)
	if err != nil {
		t.Fatal("could not create pipe pre-creation fixture")
	}
	if _, err := createPipe(name, sid, true); err == nil {
		t.Fatal("first-instance check allowed a pre-created pipe name")
	}
	if err := syscall.CloseHandle(precreated); err != nil {
		t.Fatal("could not close pipe pre-creation fixture")
	}
	stale, err := createPipe(name, sid, true)
	if err != nil {
		t.Fatal("closed named-pipe namespace could not be reused")
	}
	if err := syscall.CloseHandle(stale); err != nil {
		t.Fatal("could not close named-pipe namespace fixture")
	}
}

func TestWindowsClientAcceptsSyntheticFakeBroker(t *testing.T) {
	name, err := newPipeName()
	if err != nil {
		t.Fatal("could not create synthetic fake-broker pipe name")
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal("could not read current token SID")
	}
	handle, err := createPipe(name, sid, true)
	if err != nil {
		t.Fatal("could not create synthetic fake-broker pipe")
	}
	defer syscall.CloseHandle(handle)

	value, err := randomSyntheticValue()
	if err != nil {
		t.Fatal("could not create a synthetic fake-broker response")
	}
	type observation struct {
		sid     string
		request request
		raw     []byte
		err     error
	}
	observed := make(chan observation, 1)
	go func() {
		if err := connectPipe(handle, pipeTimeoutMillis); err != nil {
			observed <- observation{err: err}
			return
		}
		raw, readErr := readFrame(handle, true)
		input, parseErr := parseRequest(raw)
		clientSID, sidErr := impersonatedClientSID(handle)
		result := observation{
			sid: clientSID, request: input, raw: raw,
			err: errors.Join(readErr, parseErr, sidErr),
		}
		if result.err == nil && len(raw) <= maxRequestBytes {
			result.err = writeFrame(handle, reply{Status: "resolved", Value: value}, true)
		}
		observed <- result
	}()

	result := runHelper(t, "native", map[string]string{
		"KREDOXI_IPC_ENDPOINT":        name,
		"KREDOXI_IPC_EXPECTED_DIGEST": syntheticValueDigest(value),
	}, nil)
	if result.err != nil || !strings.Contains(result.stdout, "ipc-helper:native=resolved") {
		t.Fatal("client did not accept the fake pipe's synthetic response")
	}
	select {
	case evidence := <-observed:
		if evidence.err != nil || evidence.sid != sid ||
			evidence.request.Reference != testReference ||
			evidence.request.ClaimedPrincipal != "sid:S-1-5-18" ||
			evidence.request.ClaimedUID != 0 || evidence.request.ClaimedPID != 1 {
			t.Fatal("fake pipe did not observe the expected request and actual client token SID")
		}
		if strings.Contains(string(evidence.raw), value) ||
			strings.Contains(string(evidence.raw), "private_key") {
			t.Fatal("client request exposed synthetic response or private-key material")
		}
	case <-time.After(pipeTimeoutMillis*time.Millisecond + time.Second):
		t.Fatal("fake pipe did not receive the client request")
	}
	assertOutputDoesNotContain(t, result.stdout+result.stderr, []byte(value))
}

func TestWindowsDuplicatedClientHandleRetainsAccess(t *testing.T) {
	harness := newWindowsHarness(t)
	namePointer, err := syscall.UTF16PtrFromString(harness.name)
	if err != nil {
		t.Fatal("could not encode named-pipe endpoint")
	}
	waited, _, _ := procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(namePointer)), pipeTimeoutMillis)
	if waited == 0 {
		t.Fatal("named pipe was not ready for duplicate-handle test")
	}
	clientHandle, err := syscall.CreateFile(
		namePointer, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|securitySQOSPresent|securityImpersonation, 0,
	)
	if err != nil {
		t.Fatal("could not connect duplicate-handle test client")
	}
	flags, err := getHandleFlags(clientHandle)
	if err != nil || flags&syscall.HANDLE_FLAG_INHERIT != 0 {
		_ = syscall.CloseHandle(clientHandle)
		t.Fatal("client pipe handle was inheritable")
	}
	duplicate, err := duplicateHandle(clientHandle)
	if err != nil {
		_ = syscall.CloseHandle(clientHandle)
		t.Fatal("could not duplicate connected pipe handle")
	}
	if err := syscall.CloseHandle(clientHandle); err != nil {
		_ = syscall.CloseHandle(duplicate)
		t.Fatal("could not close original client pipe handle")
	}
	data, err := json.Marshal(request{Reference: testReference, ClaimedPrincipal: "forged"})
	if err != nil {
		t.Fatal("could not encode duplicate-handle request")
	}
	frame := make([]byte, len(data)+2)
	binary.LittleEndian.PutUint16(frame, uint16(len(data)))
	copy(frame[2:], data)
	if err := writeExactPipe(duplicate, frame, false); err != nil {
		_ = syscall.CloseHandle(duplicate)
		t.Fatal("duplicated handle could not use the already-authorized pipe")
	}
	responseData, err := readFrame(duplicate, false)
	_ = syscall.CloseHandle(duplicate)
	if err != nil {
		t.Fatal("duplicated pipe handle could not receive its response")
	}
	var response reply
	if err := json.Unmarshal(responseData, &response); err != nil || response.Status != "resolved" ||
		syntheticValueDigest(response.Value) != syntheticValueDigest(harness.broker.values[testReference]) {
		t.Fatal("duplicated pipe handle did not retain the connected capability")
	}
}

func TestWindowsClientDisconnectDoesNotResolve(t *testing.T) {
	harness := newWindowsHarness(t)
	namePointer, err := syscall.UTF16PtrFromString(harness.name)
	if err != nil {
		t.Fatal("could not encode named-pipe endpoint")
	}
	waited, _, _ := procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(namePointer)), pipeTimeoutMillis)
	if waited == 0 {
		t.Fatal("named pipe was not ready for disconnect test")
	}
	client, err := syscall.CreateFile(
		namePointer,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|securitySQOSPresent|securityImpersonation,
		0,
	)
	if err != nil {
		t.Fatal("could not connect the incomplete-request client")
	}
	select {
	case <-harness.connected:
	case <-time.After(2 * time.Second):
		_ = syscall.CloseHandle(client)
		t.Fatal("named-pipe broker did not accept the incomplete-request client")
	}
	var length [2]byte
	binary.LittleEndian.PutUint16(length[:], 10)
	if err := writeExactPipe(client, length[:], false); err != nil {
		_ = syscall.CloseHandle(client)
		t.Fatal("could not send the incomplete request frame")
	}
	if err := syscall.CloseHandle(client); err != nil {
		t.Fatal("could not terminate the incomplete-request client")
	}
	select {
	case observed := <-harness.evidence:
		if observed.status != "invalid_request" {
			t.Fatal("disconnected client did not fail as an invalid request")
		}
	case <-time.After(pipeTimeoutMillis*time.Millisecond + time.Second):
		t.Fatal("broker did not observe the disconnected client")
	}
	if got := harness.broker.lookups.Load(); got != 0 {
		t.Fatal("disconnected request reached the provider")
	}
	select {
	case <-harness.done:
	case <-time.After(2 * time.Second):
		t.Fatal("named-pipe broker did not terminate after client exit")
	}
}

func TestWindowsBrokerTerminationWithoutClient(t *testing.T) {
	harness := newWindowsHarness(t)
	if err := harness.close(); err != nil {
		t.Fatal("could not close the named-pipe broker")
	}
	select {
	case <-harness.done:
	case <-time.After(2 * time.Second):
		t.Fatal("named-pipe broker did not stop without a client")
	}
	if got := harness.broker.lookups.Load(); got != 0 {
		t.Fatal("broker shutdown without a client reached the provider")
	}
}

func TestWindowsConcurrentNativeClients(t *testing.T) {
	brokerSID, err := currentUserSID()
	if err != nil {
		t.Fatal("could not read broker token SID")
	}
	value, err := randomSyntheticValue()
	if err != nil {
		t.Fatal("could not generate synthetic IPC value")
	}
	const clients = 6
	broker := newExperimentBroker("sid:"+brokerSID, testReference, value)
	harnesses := make([]*windowsHarness, clients)
	type clientResult struct {
		result   helperResult
		expected string
	}
	results := make(chan clientResult, clients)
	var wait sync.WaitGroup
	for index := range harnesses {
		name, err := newPipeName()
		if err != nil {
			t.Fatal("could not create concurrent pipe name")
		}
		harnesses[index] = startWindowsHarness(t, name, brokerSID, value)
		harnesses[index].broker = broker
		reference, expected := testReference, "resolved"
		if index%2 != 0 {
			reference, expected = "kredoxi://v1/demo/other/password", "policy_denied"
		}
		wait.Add(1)
		go func(harness *windowsHarness, reference, expected string) {
			defer wait.Done()
			extra := map[string]string{
				"KREDOXI_IPC_ENDPOINT":        harness.name,
				"KREDOXI_IPC_REFERENCE":       reference,
				"KREDOXI_IPC_EXPECTED_STATUS": expected,
			}
			if expected == "resolved" {
				extra["KREDOXI_IPC_EXPECTED_DIGEST"] = syntheticValueDigest(value)
			}
			results <- clientResult{
				result: runHelper(t, "native", extra, nil), expected: expected,
			}
		}(harnesses[index], reference, expected)
	}
	wait.Wait()
	close(results)
	for result := range results {
		if result.result.err != nil ||
			!strings.Contains(result.result.stdout, "ipc-helper:native="+result.expected) {
			t.Fatal("concurrent named-pipe client had an unexpected authorization result")
		}
	}
	if got := broker.lookups.Load(); got != clients/2 {
		t.Fatal("concurrent denied requests reached provider or authorized requests were not looked up exactly once")
	}
}

func TestWindowsRemotePipeDenialFlagIsConfigured(t *testing.T) {
	if pipeRejectRemoteClient != 0x00000008 {
		t.Fatal("remote named-pipe clients are not rejected by configuration")
	}
	t.Skip("blocked: no separate authorized Windows host is available to measure remote-client denial")
}
