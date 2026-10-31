package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kredoxi/kredoxi/internal/devruntime"
)

const (
	maxCapturedOutput = 1 << 20
	maxDiagnosticLine = 4096
	startupTimeout    = 30 * time.Second
	shutdownTimeout   = 10 * time.Second
	controlTimeout    = 3 * time.Second
)

type outputCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
	changed  chan struct{}
}

func newOutputCapture() *outputCapture {
	return &outputCapture{changed: make(chan struct{})}
}

func (c *outputCapture) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	available := maxCapturedOutput - len(c.data)
	if available > 0 {
		if available > len(data) {
			available = len(data)
		}
		c.data = append(c.data, data[:available]...)
	}
	if available < len(data) {
		c.overflow = true
	}
	close(c.changed)
	c.changed = make(chan struct{})
	return len(data), nil
}

func (c *outputCapture) snapshot() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.data...), c.overflow
}

func (c *outputCapture) waitContains(value string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		c.mu.Lock()
		if bytes.Contains(c.data, []byte(value)) {
			c.mu.Unlock()
			return true
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			return false
		}
	}
}

type processOutput struct {
	stdout               *outputCapture
	stderr               *outputCapture
	registerConfidential func([]byte)
	registerChild        func(*childProcess)
}

type outputSet struct {
	mu            sync.Mutex
	streams       map[string]*outputCapture
	confidential  [][]byte
	children      []*childProcess
	tempDirectory string
}

func newOutputSet() *outputSet {
	return &outputSet{streams: make(map[string]*outputCapture)}
}

func (o *outputSet) capture(name string) *outputCapture {
	o.mu.Lock()
	defer o.mu.Unlock()
	capture := o.streams[name]
	if capture == nil {
		capture = newOutputCapture()
		o.streams[name] = capture
	}
	return capture
}

func (o *outputSet) process(name string) processOutput {
	return processOutput{
		stdout: o.capture(name + ".stdout"), stderr: o.capture(name + ".stderr"),
		registerConfidential: o.registerConfidential, registerChild: o.registerChild,
	}
}

func (o *outputSet) registerChild(child *childProcess) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.children = append(o.children, child)
}

func (o *outputSet) registerConfidential(data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.confidential = append(o.confidential, data)
}

func (o *outputSet) assertRedacted(values ...[]byte) error {
	o.mu.Lock()
	streams := make(map[string]*outputCapture, len(o.streams))
	for name, capture := range o.streams {
		streams[name] = capture
	}
	confidential := append([][]byte(nil), o.confidential...)
	o.mu.Unlock()
	values = append(values, confidential...)
	for _, capture := range streams {
		data, overflow := capture.snapshot()
		if overflow {
			return errors.New("captured diagnostics exceeded the configured limit")
		}
		for _, value := range values {
			if len(value) != 0 && bytes.Contains(data, value) {
				return errors.New("diagnostics contain contract-confidential material")
			}
		}
	}
	return nil
}

func (o *outputSet) writeSupervisor(stdout, stderr io.Writer) error {
	for _, item := range []struct {
		name   string
		writer io.Writer
	}{{"supervisor.stdout", stdout}, {"supervisor.stderr", stderr}} {
		data, overflow := o.capture(item.name).snapshot()
		if overflow {
			return errors.New("supervisor diagnostics exceeded the configured limit")
		}
		if len(data) > 0 {
			if _, err := item.writer.Write(data); err != nil {
				return errors.New("supervisor output failed")
			}
		}
	}
	return nil
}

type lineCapture struct {
	capture  *outputCapture
	name     string
	mu       sync.Mutex
	line     []byte
	discard  bool
	ready    chan string
	acks     chan devruntime.ControlAck
	eventErr chan struct{}
}

func newLineCapture(capture *outputCapture, name string, ready chan string, acks chan devruntime.ControlAck, eventErr chan struct{}) *lineCapture {
	return &lineCapture{
		capture: capture, name: name, ready: ready, acks: acks, eventErr: eventErr,
	}
}

func (w *lineCapture) Write(data []byte) (int, error) {
	_, _ = w.capture.Write(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, value := range data {
		if value == '\n' {
			if !w.discard {
				w.processLine(string(w.line))
			}
			w.line = w.line[:0]
			w.discard = false
			continue
		}
		if !w.discard {
			if len(w.line) == maxDiagnosticLine {
				w.line = w.line[:0]
				w.discard = true
				w.signalError()
			} else {
				w.line = append(w.line, value)
			}
		}
	}
	return len(data), nil
}

func (w *lineCapture) processLine(line string) {
	prefix := "KREDOXI_READY " + w.name
	if line == prefix {
		select {
		case w.ready <- "":
		default:
			w.signalError()
		}
		return
	}
	if strings.HasPrefix(line, prefix+" ") {
		select {
		case w.ready <- strings.TrimPrefix(line, prefix+" "):
		default:
			w.signalError()
		}
		return
	}
	if strings.HasPrefix(line, "KREDOXI_ACK ") {
		ack, err := devruntime.ParseControlAck(line)
		if err != nil {
			w.signalError()
			return
		}
		select {
		case w.acks <- ack:
		default:
			w.signalError()
		}
	}
}

func (w *lineCapture) signalError() {
	select {
	case w.eventErr <- struct{}{}:
	default:
	}
}

type childProcess struct {
	name        string
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	ready       chan string
	acks        chan devruntime.ControlAck
	eventErr    chan struct{}
	finished    chan struct{}
	mu          sync.Mutex
	result      error
	cleanupErr  error
	controlMu   sync.Mutex
	nextControl uint64
	output      processOutput
	cleanup     func() error
}

func startExecutable(binary, name string, args []string, bootstrap any, keepInput bool, output processOutput, readyLimit time.Duration) (*childProcess, string, error) {
	command := exec.Command(binary, args...)
	command.Env = minimalProcessEnvironment()
	return startCommand(command, name, bootstrap, keepInput, output, readyLimit)
}

func startCommand(command *exec.Cmd, name string, bootstrap any, keepInput bool, output processOutput, readyLimit time.Duration) (*childProcess, string, error) {
	data, err := devruntime.Encode(bootstrap)
	if err != nil {
		return nil, "", errors.New("development bootstrap failed")
	}
	if output.registerConfidential != nil {
		output.registerConfidential(data)
	}
	if err := configureCommand(command); err != nil {
		return nil, "", errors.New("process containment setup failed")
	}
	child := &childProcess{
		name: name, cmd: command, ready: make(chan string, 1),
		acks: make(chan devruntime.ControlAck, 32), eventErr: make(chan struct{}, 1),
		finished: make(chan struct{}), output: output,
	}
	command.Stdout = output.stdout
	command.Stderr = newLineCapture(output.stderr, name, child.ready, child.acks, child.eventErr)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, "", errors.New("process startup failed")
	}
	child.stdin = input
	if err := command.Start(); err != nil {
		_ = input.Close()
		return nil, "", errors.New("process startup failed")
	}
	cleanup, err := containStartedProcess(command.Process)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = input.Close()
		return nil, "", errors.New("process containment setup failed")
	}
	child.cleanup = cleanup
	if output.registerChild != nil {
		output.registerChild(child)
	}
	go func() {
		waitErr := command.Wait()
		var cleanupErr error
		if child.cleanup != nil {
			cleanupErr = child.cleanup()
		}
		child.mu.Lock()
		child.result = waitErr
		child.cleanupErr = cleanupErr
		close(child.finished)
		child.mu.Unlock()
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := io.Copy(input, bytes.NewReader(data))
		if writeErr == nil && !keepInput {
			writeErr = input.Close()
		}
		writeDone <- writeErr
	}()
	timer := time.NewTimer(readyLimit)
	defer timer.Stop()
	readyEvents := child.ready
	writeEvents := (<-chan error)(writeDone)
	var address string
	readyReceived := false
	for !readyReceived || writeEvents != nil {
		select {
		case writeErr := <-writeEvents:
			writeEvents = nil
			if writeErr != nil {
				cleanupErr := abortStartup(child, nil)
				return child, "", errors.Join(errors.New("process bootstrap failed"), cleanupErr)
			}
		case candidate := <-readyEvents:
			if candidate != "" {
				if err := validateAddress(candidate); err != nil {
					cleanupErr := abortStartup(child, writeEvents)
					return child, "", errors.Join(err, cleanupErr)
				}
			}
			address = candidate
			readyReceived = true
			readyEvents = nil
		case <-child.finished:
			cleanupErr := abortStartup(child, writeEvents)
			return child, "", errors.Join(errors.New("process exited before readiness"), cleanupErr)
		case <-child.eventErr:
			cleanupErr := abortStartup(child, writeEvents)
			return child, "", errors.Join(errors.New("process readiness diagnostics invalid"), cleanupErr)
		case <-timer.C:
			cleanupErr := abortStartup(child, writeEvents)
			return child, "", errors.Join(errors.New("process startup timed out"), cleanupErr)
		}
	}
	return child, address, nil
}

func abortStartup(child *childProcess, writeDone <-chan error) error {
	terminateErr := child.terminate(shutdownTimeout)
	if writeDone == nil {
		return terminateErr
	}
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()
	select {
	case <-writeDone:
		return terminateErr
	case <-timer.C:
		return errors.Join(terminateErr, errors.New("process bootstrap pipe did not close"))
	}
}

func minimalProcessEnvironment() []string {
	keys := []string{
		"PATH", "HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
		"GOPATH", "GOCACHE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR",
	}
	if runtime.GOOS != "windows" {
		keys = []string{"PATH", "HOME", "GOPATH", "GOCACHE", "TMPDIR"}
	}
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			environment = append(environment, key+"="+value)
		}
	}
	return environment
}

func (p *childProcess) control(operation string, timeout time.Duration) (devruntime.ControlAck, error) {
	return p.controlWithSent(operation, timeout, nil)
}

func (p *childProcess) controlWithSent(operation string, timeout time.Duration, sent chan<- struct{}) (devruntime.ControlAck, error) {
	p.controlMu.Lock()
	defer p.controlMu.Unlock()
	p.mu.Lock()
	if p.result != nil || isClosed(p.finished) {
		p.mu.Unlock()
		return devruntime.ControlAck{}, errors.New("process exited before control acknowledgement")
	}
	p.nextControl++
	command := devruntime.ControlCommand{ID: p.nextControl, Operation: operation}
	p.mu.Unlock()
	data, err := devruntime.EncodeControl(command)
	if err != nil {
		return devruntime.ControlAck{}, err
	}
	if _, err := p.stdin.Write(data); err != nil {
		return devruntime.ControlAck{}, errors.New("process control write failed")
	}
	if sent != nil {
		close(sent)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ack := <-p.acks:
		if ack.ID != command.ID || ack.Operation != command.Operation {
			return devruntime.ControlAck{}, errors.New("unexpected or stale control acknowledgement")
		}
		return ack, nil
	case <-p.eventErr:
		return devruntime.ControlAck{}, errors.New("malformed process diagnostic event")
	case <-p.finished:
		return devruntime.ControlAck{}, errors.New("process exited before control acknowledgement")
	case <-timer.C:
		return devruntime.ControlAck{}, errors.New("process control acknowledgement timed out")
	}
}

func (p *childProcess) requireApplied(operation string, timeout time.Duration) error {
	ack, err := p.control(operation, timeout)
	if err != nil {
		return err
	}
	if !ack.Applied {
		return errors.New("process rejected control operation")
	}
	return nil
}

func (p *childProcess) wait(timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.finished:
		p.mu.Lock()
		result, cleanupErr := p.result, p.cleanupErr
		p.mu.Unlock()
		if cleanupErr != nil {
			return errors.New("child process containment cleanup failed")
		}
		if result != nil {
			return errors.New("child process failed")
		}
		return nil
	case <-timer.C:
		return errors.New("child process shutdown timed out")
	}
}

func (p *childProcess) closeInput() error {
	if p.stdin == nil {
		return nil
	}
	if err := p.stdin.Close(); err != nil && !isClosed(p.finished) {
		return errors.New("process input close failed")
	}
	return nil
}

func (p *childProcess) stopBroker() error {
	return p.stopControlled()
}

func (p *childProcess) stopControlled() error {
	if p == nil {
		return nil
	}
	if err := p.requireApplied("stop", controlTimeout); err != nil {
		_ = p.terminate(shutdownTimeout)
		return err
	}
	if err := p.closeInput(); err != nil {
		_ = p.terminate(shutdownTimeout)
		return err
	}
	if err := p.wait(shutdownTimeout); err != nil {
		_ = p.terminate(shutdownTimeout)
		return err
	}
	return nil
}

func (p *childProcess) terminate(timeout time.Duration) error {
	if p == nil {
		return nil
	}
	if isClosed(p.finished) {
		p.mu.Lock()
		cleanupErr := p.cleanupErr
		p.mu.Unlock()
		if cleanupErr != nil {
			return errors.New("child process containment cleanup failed")
		}
		return nil
	}
	closeErr := p.closeInput()
	if p.cmd.Process == nil {
		return errors.New("child process handle unavailable")
	}
	killErr := p.cmd.Process.Kill()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.finished:
		p.mu.Lock()
		cleanupErr := p.cleanupErr
		p.mu.Unlock()
		if cleanupErr != nil {
			return errors.New("child process containment cleanup failed")
		}
		return nil
	case <-timer.C:
		if isClosed(p.finished) {
			p.mu.Lock()
			cleanupErr := p.cleanupErr
			p.mu.Unlock()
			if cleanupErr != nil {
				return errors.New("child process containment cleanup failed")
			}
			return nil
		}
		if killErr != nil {
			return errors.Join(closeErr, errors.New("child process termination failed"))
		}
		return errors.Join(closeErr, errors.New("child process termination timed out"))
	}
}

func isClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func allProcessesStopped(outputs *outputSet) bool {
	outputs.mu.Lock()
	processes := append([]*childProcess(nil), outputs.children...)
	outputs.mu.Unlock()
	for _, process := range processes {
		if process != nil {
			process.mu.Lock()
			stopped := isClosed(process.finished) && process.cleanupErr == nil
			process.mu.Unlock()
			if !stopped {
				return false
			}
		}
	}
	return true
}

func validateAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host != "127.0.0.1" || number < 1 || number > 65535 {
		return errors.New("child returned an invalid loopback address")
	}
	return nil
}

func buildExecutables(root string, outputs *outputSet) (map[string]string, error) {
	directory, err := os.MkdirTemp("", "kredoxi-demo-")
	if err != nil {
		return nil, errors.New("temporary build directory unavailable")
	}
	outputs.mu.Lock()
	outputs.tempDirectory = directory
	outputs.mu.Unlock()
	binaries := make(map[string]string, 3)
	for _, entry := range []struct {
		name        string
		packagePath string
	}{
		{"broker", "./cmd/broker"},
		{"consumer", "./cmd/consumer"},
		{"service", "./cmd/synthetic-service"},
	} {
		name, packagePath := entry.name, entry.packagePath
		filename := name
		if runtime.GOOS == "windows" {
			filename += ".exe"
		}
		binary := filepath.Join(directory, filename)
		capture := outputs.capture("build." + name + ".stdout")
		diagnostics := outputs.capture("build." + name + ".stderr")
		command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, packagePath)
		command.Dir = root
		command.Env = append(minimalProcessEnvironment(),
			"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local",
			"GOPROXY=off", "GOSUMDB=off", "CGO_ENABLED=0")
		command.Stdout = capture
		command.Stderr = diagnostics
		if err := command.Run(); err != nil {
			return nil, errors.New("development executable build failed")
		}
		binaries[name] = binary
	}
	return binaries, nil
}

func removeBuildDirectory(outputs *outputSet) error {
	outputs.mu.Lock()
	directory := outputs.tempDirectory
	outputs.mu.Unlock()
	if directory == "" {
		return nil
	}
	if err := os.RemoveAll(directory); err != nil {
		return errors.New("temporary executable cleanup failed")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		return errors.New("temporary executable cleanup was not confirmed")
	}
	return nil
}

func assertBuildDirectoryRedacted(outputs *outputSet, values ...[]byte) error {
	outputs.mu.Lock()
	directory := outputs.tempDirectory
	confidential := append([][]byte(nil), outputs.confidential...)
	outputs.mu.Unlock()
	values = append(values, confidential...)
	if directory == "" {
		return nil
	}
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("temporary executable inspection failed")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected temporary build symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("unexpected temporary build artifact")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return errors.New("temporary executable inspection failed")
		}
		for _, value := range values {
			if len(value) != 0 && bytes.Contains(data, value) {
				return errors.New("temporary executable directory contains confidential material")
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
