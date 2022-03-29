package stlog

import (
	"reflect"
	"testing"
)

type spyLogger struct {
	level                                            LogLevel
	calledError, calledWarn, calledInfo, calledDebug bool
}

func (s *spyLogger) setLevel(level LogLevel) {
	s.level = level
}

func (s *spyLogger) error(format string, v ...interface{}) {
	s.calledError = true
}

func (s *spyLogger) warn(format string, v ...interface{}) {
	s.calledWarn = true
}

func (s *spyLogger) info(format string, v ...interface{}) {
	s.calledInfo = true
}

func (s *spyLogger) debug(format string, v ...interface{}) {
	s.calledDebug = true
}

func TestSetOutput(t *testing.T) {
	SetOutput(StdError)
	if _, ok := stl.(*standardLogger); !ok {
		t.Errorf("SetOutput(StdError) = %v, want *standardLogger", reflect.TypeOf(stl))
	}

	SetOutput(KernelSyslog)
	switch stl.(type) {
	case *kernelLogger, *standardLogger:
		// pass
	default:
		t.Errorf("SetOutput(KernelSyslog) = %v, want *kernelLogger or *standardLogger (fallback)", reflect.TypeOf(stl))
		// kernel syslog will only work when running test as root
	}
}

func TestSetLevel(t *testing.T) {
	spy := &spyLogger{}
	stl = spy

	for _, level := range []LogLevel{
		ErrorLevel,
		WarnLevel,
		InfoLevel,
		DebugLevel,
	} {
		SetLevel(level)
		if spy.level != level {
			t.Errorf("SetLevel(%v) = %v, want %v", level, spy.level, level)
		}
	}

	SetLevel(DebugLevel + 1)
	if spy.level != DebugLevel {
		t.Errorf("SetLevel(unknown) = %v, want %v", spy.level, DebugLevel)
	}
}

func TestLogCalls(t *testing.T) {
	spy := &spyLogger{}
	stl = spy

	Error("foo")
	if !spy.calledError {
		t.Errorf("stl.error() was not called")
	}

	Warn("foo")
	if !spy.calledWarn {
		t.Errorf("stl.warn() was not called")
	}

	Info("foo")
	if !spy.calledInfo {
		t.Errorf("stl.info() was not called")
	}

	Debug("foo")
	if !spy.calledDebug {
		t.Errorf("stl.debug() was not called")
	}
}
