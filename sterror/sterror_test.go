package sterror

import (
	"fmt"
	"testing"
)

const (
	emptyOp        Op    = ""
	filledOpOne    Op    = "Calculate Checksum"
	filledOpTwo    Op    = "another operation"
	emptyScope     Scope = ""
	filledScopeOne Scope = Network
	filledScopeTwo Scope = Host
	emptyInfo      Info  = ""
	filledInfo     Info  = "a lot of info"
)

var (
	errEmpty             error
	errFilled            = fmt.Errorf("this is an error")
	errErrorEmpty        = Error{"", "", "", nil}
	errErrorPartialOne   = Error{emptyOp, filledScopeOne, filledInfo, errEmpty}
	errErrorPartialTwo   = Error{filledOpTwo, filledScopeTwo, filledInfo, errEmpty}
	errErrorPartialThree = Error{filledOpTwo, emptyScope, emptyInfo, errEmpty}
	errErrorFilledOne    = Error{filledOpOne, filledScopeOne, filledInfo, errFilled}
	errErrorFilledTwo    = Error{filledOpTwo, filledScopeOne, filledInfo, errFilled}
	errErrorFilledThree  = Error{filledOpTwo, filledScopeTwo, filledInfo, errFilled}
	errErrorWrapped      = Error{emptyOp, filledScopeOne, emptyInfo, &errErrorFilledOne}
)

func TestNewError(t *testing.T) {
	t.Run("check if generated error is correct", func(t *testing.T) {
		cases := []struct{ got, want error }{
			{E(), errErrorEmpty},
			{E(filledScopeOne, filledInfo), errErrorPartialOne},
			{E(filledOpOne, filledScopeOne, filledInfo, errFilled), errErrorFilledOne},
			{E(filledOpTwo), errErrorPartialThree},
			{E(filledScopeOne, errErrorFilledOne), errErrorWrapped},
		}

		for _, c := range cases {
			assertEqualString(t, c.got.Error(), c.want.Error())
		}
	})
}

func TestEqual(t *testing.T) {
	t.Run("check if errors match", func(t *testing.T) {
		cases := []struct{ got, want Error }{
			{E(), errErrorEmpty},
			{E(filledScopeOne, filledInfo), errErrorPartialOne},
			{E(filledOpOne, filledScopeOne, filledInfo, errFilled), errErrorFilledOne},
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
			{E(filledOpOne, filledInfo, filledScopeOne, filledInfo, errFilled), errErrorFilledOne},
			{E(filledOpTwo, 2), errErrorPartialThree},
			{E(filledScopeOne, errErrorFilledOne, "aa"), errErrorWrapped},
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
		tb.Errorf("wanted: %v\n but got: %v.", want, got)
	}
}

func assertEqual(tb testing.TB, got, want Error) {
	tb.Helper()

	if !Equal(got, want) {
		tb.Errorf("wanted: %v\n and got: %v\n did not match.", want, got)
	}
}

func assertNotEqual(tb testing.TB, got, want Error) {
	tb.Helper()

	if Equal(got, want) {
		tb.Errorf("wanted: %v\n and got: %v\n did match.", want, got)
	}
}
