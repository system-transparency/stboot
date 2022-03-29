// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package stlog

import (
	"bytes"
	"os"
	"testing"
)

func TestSTLog(t *testing.T) {
	for _, tt := range []struct {
		name   string
		level  LogLevel
		format string
		input  string
		want   string
	}{
		{
			name:   "LogLevel Zero valid",
			level:  ErrorLevel,
			format: "%s",
			input:  "LogLevel 0",
			want:   "[ERROR] stboot: LogLevel 0\n",
		},
		{
			name:   "LogLevel One valid",
			level:  WarnLevel,
			format: "%s",
			input:  "LogLevel 1",
			want:   "[WARN] stboot: LogLevel 1\n",
		},
		{
			name:   "LogLevel Two valid",
			level:  InfoLevel,
			format: "%s",
			input:  "LogLevel 2",
			want:   "[INFO] stboot: LogLevel 2\n",
		},
		{
			name:   "LogLevel Three valid",
			level:  DebugLevel,
			format: "%s",
			input:  "LogLevel 3",
			want:   "[DEBUG] stboot: LogLevel 3\n",
		},
		{
			name:   "LogLevel invalid",
			level:  5,
			format: "%s",
			input:  "LogLevel invalid",
			want:   "[DEBUG] stboot: LogLevel invalid\n",
		},
	} {
		t.Run(tt.name+" Std Logger", func(t *testing.T) {
			buf := bytes.Buffer{}
			l := newStandardLogger(&buf)
			l.setLevel(tt.level)
			switch tt.level {
			case ErrorLevel:
				l.error(tt.format, tt.input)
			case WarnLevel:
				l.warn(tt.format, tt.input)
			case InfoLevel:
				l.info(tt.format, tt.input)
			case DebugLevel:
				l.debug(tt.format, tt.input)
			default:
				// If LogLevel is unknown it defaults to Debug
				l.debug(tt.format, tt.input)
			}
			got := buf.String()
			if got != tt.want {
				t.Errorf("Test: %s failed.\nGot : %sWant: %s", tt.name, got, tt.want)
			}
		})
		// Kernel Logger needs root to open /dev/kmsg
		t.Run(tt.name+" Kernel Logger", func(t *testing.T) {
			if os.Getuid() != 0 {
				t.Skip("root required for this test")
			}
			l, err := newKernlLogger()
			if err != nil {
				t.Fatalf("newKernelLogger()=l, %q, want nil", err)
			}
			l.setLevel(tt.level)
			switch tt.level {
			case ErrorLevel:
				l.error(tt.format, tt.input)
			case WarnLevel:
				l.warn(tt.format, tt.input)
			case InfoLevel:
				l.info(tt.format, tt.input)
			case DebugLevel:
				l.debug(tt.format, tt.input)
			default:
				// If LogLevel is unknown it defaults to Debug
				l.debug(tt.format, tt.input)
			}
		})
	}

}
