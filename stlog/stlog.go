// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stlog adds log levels on top of the log facility in the standard library.
package stlog

import (
	"fmt"
	"log"
	"sync/atomic"
)

const (
	errorTag string = "[ERROR] "
	warnTag  string = "[WARN] "
	infoTag  string = "[INFO] "
	debugTag string = "[DEBUG] "
)

type LogLevel int

const (
	ErrorLevel LogLevel = iota
	WarnLevel
	InfoLevel
	DebugLevel
)

//nolint:gochecknoglobals
var currentLogLevel int32

//nolint:gochecknoinits
func init() {
	currentLogLevel = int32(DebugLevel)
}

// SetLevel sets the logging level.
func SetLevel(level LogLevel) {
	switch level {
	case ErrorLevel, InfoLevel, WarnLevel, DebugLevel:

	default:
		level = DebugLevel
	}

	atomic.StoreInt32(&currentLogLevel, int32(level))
}

// GetLevel return the log level set.
func Level() LogLevel {
	return LogLevel(atomic.LoadInt32(&currentLogLevel))
}

// Error prints error messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf.
func Error(format string, v ...interface{}) {
	if Level() >= ErrorLevel {
		log.Print(errorTag + fmt.Sprintf(format, v...))
	}
}

// Warn prints waring messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf.
func Warn(format string, v ...interface{}) {
	if Level() >= WarnLevel {
		log.Print(warnTag + fmt.Sprintf(format, v...))
	}
}

// Info prints info messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf.
func Info(format string, v ...interface{}) {
	if Level() >= InfoLevel {
		log.Print(infoTag + fmt.Sprintf(format, v...))
	}
}

// Debug prints debug messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf.
func Debug(format string, v ...interface{}) {
	if Level() >= DebugLevel {
		log.Print(debugTag + fmt.Sprintf(format, v...))
	}
}
