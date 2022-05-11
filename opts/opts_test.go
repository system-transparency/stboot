package opts

import (
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

const ErrStubLoader = Error("stubLoader error")

func (s *stubLoader) Load(o *Opts) error {
	if s.fail {
		return ErrStubLoader
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
			errType: ErrNonNil,
		},
	}

	for _, tt := range tests {
		got, err := NewOpts(tt.loaders...)
		assert(t, err, tt.errType, got, tt.want)
	}
}
