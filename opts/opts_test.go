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

		if tt.errType != nil {
			if err == nil {
				t.Fatal("expect an error")
			}

			goterr, wanterr := reflect.TypeOf(err), reflect.TypeOf(tt.errType)
			if goterr != wanterr {
				t.Errorf("got %+v, want %+v", goterr, wanterr)
			}
		}

		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("got %+v, want %+v", got, tt.want)
		}

	}
}
