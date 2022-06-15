// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stlog

import (
	"errors"
	"fmt"

	"github.com/u-root/u-root/pkg/ulog"
)

type kernelLogger struct {
	out   *ulog.KLog
	level LogLevel
}

var errInitKlog = errors.New("init klog failed")

func newKernlLogger() (*kernelLogger, error) {
	klog := ulog.KernelLog
	klog.SetLogLevel(ulog.KLogNotice)

	if err := klog.SetConsoleLogLevel(ulog.KLogInfo); err != nil {
		return nil, fmt.Errorf("%w: %s", errInitKlog, err)
	}

	return &kernelLogger{
		out:   klog,
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
