// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stlog exposes leveled logging capabilities.
//
// stlog wraps two loggers and adds log levels to them:
// There is a standard  "log" package logger and another
// using the kernel syslog system.
package stlog

const (
	prefix   string = "stboot: "
	errorTag string = "[ERROR] "
	warnTag  string = "[WARN]  "
	infoTag  string = "[INFO]  "
	debugTag string = "[DEBUG] "
)

type LogLevel int

const (
	ErrorLevel LogLevel = iota
	WarnLevel
	InfoLevel
	DebugLevel
)

type LogOutput int

const (
	StdError LogOutput = iota
	KernelSyslog
)

var stl levelLoger

func init() {
	stl = newStandardLogger()
}

type levelLoger interface {
	setLevel(level LogLevel)
	error(format string, v ...interface{})
	warn(format string, v ...interface{})
	info(format string, v ...interface{})
	debug(format string, v ...interface{})
}

// SetOutput sets the packages underlying logger.
func SetOutout(o LogOutput) {
	switch o {
	case KernelSyslog:
		stl = newKernlLogger()
	default:
		stl = newStandardLogger()
	}
}

// SetLevel sets the logging level of stlog package
func SetLevel(l LogLevel) {
	switch l {
	case ErrorLevel, InfoLevel:
		stl.setLevel(l)
	default:
		stl.setLevel(DebugLevel)
	}
}

// Error prints error messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf
func Error(format string, v ...interface{}) {
	stl.error(format, v...)
}

// Warn prints waring messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf
func Warn(format string, v ...interface{}) {
	stl.warn(format, v...)
}

// Info prints info messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf
func Info(format string, v ...interface{}) {
	stl.info(format, v...)
}

// Debug prints debug messages to the currently active logger when permitted
// by the log level. Input can be formatted according to fmt.Printf
func Debug(format string, v ...interface{}) {
	stl.debug(format, v...)
}
