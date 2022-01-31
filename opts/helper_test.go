package opts

import (
	"reflect"
	"testing"
)

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
