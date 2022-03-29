package stlog

import (
	"os"
	"testing"
)

func TestKernelLogger(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root required for this test")
	}

	for _, tt := range []struct {
		name  string
		level LogLevel
		input string
	}{
		{
			name:  "LogLevel Zero valid",
			level: ErrorLevel,
			input: "LogLevel 0",
		},
		{
			name:  "LogLevel One valid",
			level: WarnLevel,
			input: "LogLevel 1",
		},
		{
			name:  "LogLevel Two valid",
			level: InfoLevel,
			input: "LogLevel 2",
		},
		{
			name:  "LogLevel Three valid",
			level: DebugLevel,
			input: "LogLevel 3",
		},
		{
			name:  "LogLevel invalid",
			level: 5,
			input: "LogLevel invalid",
		},
	} {
		t.Run(tt.name+" Kernel Logger", func(t *testing.T) {
			l, err := newKernlLogger()
			if err != nil {
				t.Fatalf("newKernelLogger()=l, %q, want nil", err)
			}
			l.setLevel(tt.level)
			switch tt.level {
			case ErrorLevel:
				l.error("%s", tt.input)
			case WarnLevel:
				l.warn("%s", tt.input)
			case InfoLevel:
				l.info("%s", tt.input)
			case DebugLevel:
				l.debug("%s", tt.input)
			default:
				// If LogLevel is unknown it defaults to Debug
				l.debug("%s", tt.input)
			}
		})
	}
}
