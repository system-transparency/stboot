package opts

import (
	"errors"
	"reflect"
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

type stubLoader struct {
	fail bool
}

func (s *stubLoader) Load(o *Opts) error {
	if s.fail {
		return errors.New("stubLoader error")
	}
	return nil
}

func TestNewOpts(t *testing.T) {
	tests := []struct {
		name    string
		loaders []Loader
		want    *Opts
		errType error
	}{
		{
			name:    "no loader",
			loaders: []Loader{},
			want:    &Opts{},
			errType: nil,
		},
		{
			name:    "bad loader",
			loaders: []Loader{&stubLoader{fail: true}},
			want:    nil,
			errType: errors.New(""),
		},
	}

	for _, tt := range tests {
		got, err := NewOpts(tt.loaders...)
		assert(t, err, tt.errType, got, tt.want)
	}
}

func assert(t *testing.T, gotErr, wantErrType error, got, want interface{}) {
	t.Helper()

	if wantErrType != nil {
		if gotErr == nil {
			t.Fatal("expect an error")
		}
		goterr, wanterr := reflect.TypeOf(gotErr), reflect.TypeOf(wantErrType)
		if goterr != wanterr {
			t.Fatalf("got %+v, want %+v", goterr, wanterr)
		}
	} else {
		if gotErr != nil {
			t.Fatalf("unexpected error: %v", gotErr)
		}
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
