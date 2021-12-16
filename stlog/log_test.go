// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package stlog

import (
	"testing"
)

func TestTest(t *testing.T) {
	t.Logf("%+v", stl)
	Debug("hello")
	Error("fooo %d", 7)
	Info("This %s is a %d", "bar", 7)

	SetLevel(InfoLevel)

	t.Logf("%+v", stl)
	Debug("hello")
	Error("fooo %d", 7)
	Info("This %s is a %d", "bar", 7)

	SetLevel(ErrorLevel)

	t.Logf("%+v", stl)
	Debug("hello")
	Error("fooo %d", 7)
	Info("This %s is a %d", "bar", 7)

	SetLevel(DebugLevel)
	SetOutput(KernelSyslog)

	t.Logf("%+v", stl)
	Debug("hello")
	Error("fooo %d", 7)
	Info("This %s is a %d", "bar", 7)

	SetOutput(StdError)

	t.Logf("%+v", stl)
	Debug("hello")
	Error("fooo %d", 7)
	Info("This %s is a %d", "bar", 7)

	SetLevel(5)
	t.Logf("%+v", stl)
	Debug("hello")
	Error("fooo %d", 7)
	Info("This %s is a %d", "bar", 7)

	SetLevel(0)
	t.Logf("%+v", stl)
	Debug("hello")
	Error("fooo %d", 7)
	Info("This %s is a %d", "bar", 7)
}
