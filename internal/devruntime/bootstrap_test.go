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
	command, err := ReadControl(bufio.NewReader(strings.NewReader("stop\n")))
	if err != nil || command != "stop" {
		t.Fatal("valid control rejected")
	}
	_, err = ReadControl(bufio.NewReader(strings.NewReader(strings.Repeat("x", 64) + "\n")))
	if err == nil {
		t.Fatal("oversized control accepted")
	}
}
