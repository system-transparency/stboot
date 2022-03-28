// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stlog

import (
	"fmt"
	"io"
	"log"
)

type standardLogger struct {
	out   *log.Logger
	level LogLevel
}

func newStandardLogger(w io.Writer) *standardLogger {
	sl := log.New(w, "", 0)
	return &standardLogger{
		out:   sl,
		level: DebugLevel,
	}
}

func (l *standardLogger) setLevel(level LogLevel) {
	l.level = level
}

func (l *standardLogger) error(format string, v ...interface{}) {
	if l.level >= ErrorLevel {
		msg := errorTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *standardLogger) warn(format string, v ...interface{}) {
	if l.level >= WarnLevel {
		msg := warnTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *standardLogger) info(format string, v ...interface{}) {
	if l.level >= InfoLevel {
		msg := infoTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *standardLogger) debug(format string, v ...interface{}) {
	if l.level >= DebugLevel {
		msg := debugTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *standardLogger) logLevel() LogLevel {
	return l.level
}
