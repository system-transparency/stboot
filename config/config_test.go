package config

import (
	"errors"
	"strings"
	"testing"
)

func TestInvalidError(t *testing.T) {
	msg := "some error message"
	err := InvalidError(msg)

	got := err.Error()
	if got != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestParseError(t *testing.T) {
	e := ParseError{Key: "someKey", Err: errors.New("some error")}

	got := e.Error()
	if !strings.Contains(got, e.Key) {
		t.Errorf("got %q, does not contain related JSON key %q", got, e.Key)
	}
}

func TestTypeError(t *testing.T) {
	e := TypeError{Key: "someKey", Value: "string value"}

	got := e.Error()
	if !strings.Contains(got, e.Key) {
		t.Errorf("got %q, does not contain related JSON key %q", got, e.Key)
	}
}
