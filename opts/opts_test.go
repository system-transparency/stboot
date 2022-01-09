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

func TestIPAddrModeString(t *testing.T) {
	tests := []struct {
		name string
		mode IPAddrMode
		want string
	}{
		{
			name: "String for default value",
			mode: IPUnset,
			want: "unset",
		},
		{
			name: "String for 'IPStatic'",
			mode: IPStatic,
			want: "static",
		},
		{
			name: "String for 'IPDynamic'",
			mode: IPDynamic,
			want: "dhcp",
		},
		{
			name: "String for unknown value",
			mode: 3,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
