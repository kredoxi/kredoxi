package main

import "testing"

func TestIndependentProcessDemo(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
