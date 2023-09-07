// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package stlog

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestStandardLoggerMessages(t *testing.T) {
	for _, tt := range []struct {
		name  string
		level LogLevel
		tag   string
		input string
	}{
		{
			name:  "LogLevel Zero valid",
			level: ErrorLevel,
			tag:   errorTag,
			input: "LogLevel 0",
		},
		{
			name:  "LogLevel One valid",
			level: WarnLevel,
			tag:   warnTag,
			input: "LogLevel 1",
		},
		{
			name:  "LogLevel Two valid",
			level: InfoLevel,
			tag:   infoTag,
			input: "LogLevel 2",
		},
		{
			name:  "LogLevel Three valid",
			level: DebugLevel,
			tag:   debugTag,
			input: "LogLevel 3",
		},
		{
			name:  "LogLevel invalid",
			level: 5,
			tag:   debugTag,
			input: "LogLevel invalid",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.Buffer{}
			log.SetOutput(&buf)
			SetLevel(tt.level)
			switch tt.level {
			case ErrorLevel:
				Error("%s", tt.input)
			case WarnLevel:
				Warn("%s", tt.input)
			case InfoLevel:
				Info("%s", tt.input)
			case DebugLevel:
				Debug("%s", tt.input)
			default:
				// If LogLevel is unknown it defaults to Debug
				Debug("%s", tt.input)
			}
			got := buf.String()
			if !strings.Contains(got, tt.tag) {
				t.Errorf("log message %q misses tag %q", got, tt.tag)
			}
			if !strings.Contains(got, tt.input) {
				t.Errorf("log message %q misses input string %q", got, tt.input)
			}
		})
	}
}

//nolint:gocognit,cyclop
func TestStandardLoggerLevel(t *testing.T) {
	for _, level := range []LogLevel{
		ErrorLevel,
		WarnLevel,
		InfoLevel,
		DebugLevel,
	} {
		t.Run("calling Error()", func(t *testing.T) {
			buf := bytes.Buffer{}
			log.SetOutput(&buf)
			SetLevel(level)

			Error("foo")

			if level >= ErrorLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling Error() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling Error() at level %v should not produce output", level)
				}
			}
		})

		t.Run("calling Warn()", func(t *testing.T) {
			buf := bytes.Buffer{}
			log.SetOutput(&buf)
			SetLevel(level)

			Warn("foo")

			if level >= WarnLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling Warn() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling Warn() at level %v should not produce output", level)
				}
			}
		})

		t.Run("calling Info()", func(t *testing.T) {
			buf := bytes.Buffer{}
			log.SetOutput(&buf)
			SetLevel(level)

			Info("foo")

			if level >= InfoLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling Info() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling Info() at level %v should not produce output", level)
				}
			}
		})

		t.Run("calling Debug()", func(t *testing.T) {
			buf := bytes.Buffer{}
			log.SetOutput(&buf)
			SetLevel(level)

			Debug("foo")

			if level >= DebugLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling Debug() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling Debug() at level %v should not produce output", level)
				}
			}
		})
	}
}
