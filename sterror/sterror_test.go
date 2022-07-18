package sterror

import (
	"errors"
	"fmt"
	"testing"
)

const (
	unspecified    string = "unspecified"
	emptyOp        Op     = ""
	fillOpOne      Op     = "Calculate Checksum"
	filledOpTwo    Op     = "another operation"
	emptyScope     Scope  = ""
	filledScopeOne Scope  = Network
	filledScopeTwo Scope  = Host
	emptyInfo      string = ""
	filledInfo     string = "a lot of info"
)

var (
	errEmpty             error
	errFilled            = fmt.Errorf("this is an error")
	errErrorEmpty        = Error{Op: "", Scope: "", Err: nil, Info: unspecified}
	errErrorPartialOne   = Error{Op: emptyOp, Scope: filledScopeOne, Err: errEmpty, Info: filledInfo}
	errErrorPartialTwo   = Error{Op: filledOpTwo, Scope: filledScopeTwo, Err: errEmpty, Info: filledInfo}
	errErrorPartialThree = Error{Op: filledOpTwo, Scope: emptyScope, Err: errEmpty, Info: emptyInfo}
	errErrorFilledOne    = Error{Op: fillOpOne, Scope: filledScopeOne, Err: errFilled, Info: filledInfo}
	errErrorFilledTwo    = Error{Op: filledOpTwo, Scope: filledScopeOne, Err: errFilled, Info: filledInfo}
	errErrorFilledThree  = Error{Op: filledOpTwo, Scope: filledScopeTwo, Err: errFilled, Info: filledInfo}
	errErrorWrapped      = Error{Op: emptyOp, Scope: filledScopeOne, Err: errErrorFilledOne, Info: emptyInfo}
)

func TestNewError(t *testing.T) {
	t.Run("check if generated error is correct", func(t *testing.T) {
		cases := []struct{ got, want error }{
			{E(), errErrorEmpty},
			{E(filledScopeOne, filledInfo), errErrorPartialOne},
			{E(fillOpOne, filledScopeOne, filledInfo, errFilled), errErrorFilledOne},
			{E(filledOpTwo), errErrorPartialThree},
			{E(filledScopeOne, errErrorFilledOne), errErrorWrapped},
		}

		for _, c := range cases {
			assertEqualString(t, c.got.Error(), c.want.Error())
		}
	})
}

func TestErrorString(t *testing.T) {
	t.Run("check if error strings match", func(t *testing.T) {
		errString1 := unspecified
		errString2 := string(filledScopeOne) + newline + filledInfo
		errString3 := string(filledScopeOne) + colon + string(fillOpOne) + newline + errFilled.Error() + newline + filledInfo
		errString4 := string(filledOpTwo)
		errString5 := string(filledScopeOne) + newline + errErrorFilledOne.Error()
		errString6 := errErrorFilledThree.Error()

		cases := []struct {
			got  Error
			want string
		}{
			{E(), errString1},
			{E(filledScopeOne, filledInfo), errString2},
			{E(fillOpOne, filledScopeOne, filledInfo, errFilled), errString3},
			{E(filledOpTwo), errString4},
			{E(filledScopeOne, errErrorFilledOne), errString5},
			{E(errErrorFilledThree), errString6},
		}

		for _, c := range cases {
			assertEqualString(t, c.got.Error(), c.want)
		}
	})
}

func TestEqual(t *testing.T) {
	t.Run("check if errors match", func(t *testing.T) {
		cases := []struct{ got, want Error }{
			{E(), errErrorEmpty},
			{E(filledScopeOne, filledInfo), errErrorPartialOne},
			{E(fillOpOne, filledScopeOne, filledInfo, errFilled), errErrorFilledOne},
			{E(filledOpTwo), errErrorPartialThree},
			{E(filledScopeOne, errErrorFilledOne), errErrorWrapped},
		}

		for _, c := range cases {
			assertEqual(t, c.got, c.want)
		}
	})
	t.Run("ignore unknown args", func(t *testing.T) {
		cases := []struct{ got, want Error }{
			{E(2), errErrorEmpty},
			{E(filledScopeOne, filledInfo, 3.5), errErrorPartialOne},
			{E(fillOpOne, filledInfo, filledScopeOne, filledInfo, errFilled), errErrorFilledOne},
			{E(filledOpTwo, 2), errErrorPartialThree},
		}

		for _, c := range cases {
			assertEqual(t, c.got, c.want)
		}
	})
	t.Run("check if errors do not match", func(t *testing.T) {
		cases := []struct{ got, want Error }{
			{errErrorEmpty, errErrorPartialOne},
			{errErrorPartialOne, errErrorPartialTwo},
			{errErrorPartialTwo, errErrorFilledTwo},
			{errErrorFilledOne, errErrorPartialTwo},
			{errErrorPartialOne, errErrorFilledOne},
			{errErrorFilledOne, errErrorWrapped},
			{errErrorFilledTwo, errErrorFilledThree},
			{errErrorWrapped, errErrorEmpty},
		}

		for _, c := range cases {
			assertNotEqual(t, c.got, c.want)
		}
	})
}

func assertEqualString(tb testing.TB, got, want string) {
	tb.Helper()

	if got != want {
		tb.Errorf("wanted: %v\n but got: %v", want, got)
	}
}

func assertEqual(tb testing.TB, got, want Error) {
	tb.Helper()

	if !equal(got, want) {
		tb.Errorf("wanted: %v\n and got: %v\n did not match.", want, got)
	}
}

func assertNotEqual(tb testing.TB, got, want Error) {
	tb.Helper()

	if equal(got, want) {
		tb.Errorf("wanted: %v\n and got: %v\n did match.", want, got)
	}
}

// equal returns true if the two provided Errors are equal.
func equal(got, want Error) bool {
	if got.Scope != want.Scope {
		return false
	}

	if got.Op != want.Op {
		return false
	}

	if got.Info != want.Info {
		return false
	}

	gotWrappedErr, typeOkGot := got.Err.(Error)
	wantWrappedErr, typeOkWant := got.Err.(Error)

	if typeOkGot != typeOkWant {
		return false
	}

	if typeOkGot {
		equal(gotWrappedErr, wantWrappedErr)
	}

	return errors.Is(gotWrappedErr, wantWrappedErr)
}
