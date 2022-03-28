// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package stlog

import (
	"bytes"
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
		t.Run(tt.name+" Std Logger", func(t *testing.T) {
			buf := bytes.Buffer{}
			l := newStandardLogger(&buf)
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
			got := buf.String()
			if !strings.Contains(got, tt.tag) {
				t.Errorf("log message %q misses tag %q", got, tt.tag)
			}
			if !strings.Contains(got, prefix) {
				t.Errorf("log message %q misses prefix %q", got, prefix)
			}
			if !strings.Contains(got, tt.input) {
				t.Errorf("log message %q misses input string %q", got, tt.input)
			}
		})
	}
}

func TestStandardLoggerLevel(t *testing.T) {
	for _, level := range []LogLevel{
		ErrorLevel,
		WarnLevel,
		InfoLevel,
		DebugLevel,
	} {
		t.Run("calling error()", func(t *testing.T) {
			buf := bytes.Buffer{}
			l := newStandardLogger(&buf)
			l.setLevel(level)

			l.error("foo")

			if l.logLevel() >= ErrorLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling error() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling error() at level %v should not produce output", level)
				}
			}
		})

		t.Run("calling warn()", func(t *testing.T) {
			buf := bytes.Buffer{}
			l := newStandardLogger(&buf)
			l.setLevel(level)

			l.warn("foo")

			if l.logLevel() >= WarnLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling warn() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling warn() at level %v should not produce output", level)
				}
			}
		})

		t.Run("calling info()", func(t *testing.T) {
			buf := bytes.Buffer{}
			l := newStandardLogger(&buf)
			l.setLevel(level)

			l.info("foo")

			if l.logLevel() >= InfoLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling info() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling info() at level %v should not produce output", level)
				}
			}
		})

		t.Run("calling debug()", func(t *testing.T) {
			buf := bytes.Buffer{}
			l := newStandardLogger(&buf)
			l.setLevel(level)

			l.debug("foo")

			if l.logLevel() >= DebugLevel {
				if len(buf.String()) == 0 {
					t.Errorf("calling debug() at level %v should produce output", level)
				}
			} else {
				if len(buf.String()) > 0 {
					t.Errorf("calling debug() at level %v should not produce output", level)
				}
			}
		})
	}
}
