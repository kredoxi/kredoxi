package devruntime

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestBootstrapRoundTripAndValidation(t *testing.T) {
	want := ServiceBootstrap{Credential: strings.Repeat("a", 64)}
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	var got ServiceBootstrap
	if err := Decode(bufio.NewReaderSize(bytes.NewReader(encoded), maxBootstrap+1), &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("bootstrap round trip changed fields")
	}
	for _, input := range []string{
		`{"credential":"x","credential":"y"}`,
		`{"credential":"x","unknown":true}`,
		`{"credential":"x"} {}`,
		`null`,
	} {
		var output ServiceBootstrap
		err := Decode(bufio.NewReaderSize(strings.NewReader(input+"\n"), maxBootstrap+1), &output)
		if err == nil {
			t.Fatalf("malformed bootstrap accepted: %s", input)
		}
	}
	oversized := strings.Repeat(" ", maxBootstrap) + "\n"
	var output ServiceBootstrap
	if err := Decode(bufio.NewReaderSize(strings.NewReader(oversized), maxBootstrap+1), &output); err == nil {
		t.Fatal("oversized bootstrap accepted")
	}
}

func TestDevelopmentControlIsBounded(t *testing.T) {
	want := ControlCommand{ID: 1, Operation: "stop"}
	encoded, err := EncodeControl(want)
	if err != nil {
		t.Fatal(err)
	}
	command, err := ReadControl(bufio.NewReader(bytes.NewReader(encoded)))
	if err != nil || command != want {
		t.Fatal("valid control rejected")
	}
	for _, input := range []string{
		`{"id":1,"operation":"stop","operation":"stop"}`,
		`{"id":1,"operation":"stop","unexpected":true}`,
		`{"id":1,"operation":"stop"} {}`,
		`{"id":0,"operation":"stop"}`,
	} {
		if _, err := ReadControl(bufio.NewReader(strings.NewReader(input + "\n"))); err == nil {
			t.Fatal("malformed control accepted")
		}
	}
	if _, err := ReadControl(bufio.NewReader(strings.NewReader(strings.Repeat("x", maxControl) + "\n"))); err == nil {
		t.Fatal("oversized control accepted")
	}
	var output bytes.Buffer
	if err := WriteControlAck(&output, ControlAck{ID: 1, Operation: "stop", Applied: true}); err != nil {
		t.Fatal(err)
	}
	ack, err := ParseControlAck(strings.TrimSuffix(output.String(), "\n"))
	if err != nil || ack != (ControlAck{ID: 1, Operation: "stop", Applied: true}) {
		t.Fatal("valid acknowledgement rejected")
	}
	for _, input := range []string{
		`KREDOXI_ACK {"id":1,"operation":"stop","applied":true,"applied":false}`,
		`KREDOXI_ACK {"id":1,"operation":"stop","applied":true,"unexpected":true}`,
		`KREDOXI_ACK {"id":0,"operation":"stop","applied":true}`,
	} {
		if _, err := ParseControlAck(input); err == nil {
			t.Fatal("malformed acknowledgement accepted")
		}
	}
}
