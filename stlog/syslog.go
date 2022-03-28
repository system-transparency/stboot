// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stlog

import (
	"fmt"

	"github.com/u-root/u-root/pkg/ulog"
)

type kernelLogger struct {
	out   *ulog.KLog
	level LogLevel
}

func newKernlLogger() (*kernelLogger, error) {
	kl := ulog.KernelLog
	kl.SetLogLevel(ulog.KLogNotice)
	if err := kl.SetConsoleLogLevel(ulog.KLogInfo); err != nil {
		return nil, err
	}
	return &kernelLogger{
		out:   kl,
		level: DebugLevel,
	}, nil
}

func (l *kernelLogger) setLevel(level LogLevel) {
	l.level = level
}

func (l *kernelLogger) error(format string, v ...interface{}) {
	if l.level >= ErrorLevel {
		msg := errorTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *kernelLogger) warn(format string, v ...interface{}) {
	if l.level >= WarnLevel {
		msg := warnTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *kernelLogger) info(format string, v ...interface{}) {
	if l.level >= InfoLevel {
		msg := infoTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *kernelLogger) debug(format string, v ...interface{}) {
	if l.level >= DebugLevel {
		msg := debugTag + prefix + fmt.Sprintf(format, v...)
		l.out.Print(msg)
	}
}

func (l *kernelLogger) logLevel() LogLevel {
	return l.level
}
