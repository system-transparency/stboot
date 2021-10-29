// This code is a somewhat simplified and changed up version of
// github.com/canonical/go-efilib credits go their authors.
// It allows interaction with the efivarfs via u-root which means
// both read and write support.

package efivarfs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// VariableAttributes uint32 identifying the variables attributes
type VariableAttributes uint32

const (
	AttributeNonVolatile                       VariableAttributes = 0x00000001
	AttributeBootserviceAccess                 VariableAttributes = 0x00000002
	AttributeRuntimeAccess                     VariableAttributes = 0x00000004
	AttributeHardwareErrorRecord               VariableAttributes = 0x00000008
	AttributeAuthenticatedWriteAccess          VariableAttributes = 0x00000010
	AttributeTimeBasedAuthenticatedWriteAccess VariableAttributes = 0x00000020
	AttributeAppendWrite                       VariableAttributes = 0x00000040
	AttributeEnhancedAuthenticatedAccess       VariableAttributes = 0x00000080
)

var (
	ErrVarsUnavailable = errors.New("no variable backend is available")
	ErrVarNotExist     = errors.New("variable does not exist")
	ErrVarPermission   = errors.New("permission denied")
)

// VariableDescriptor contains the name and GUID identifying a variable
type VariableDescriptor struct {
	Name string
	GUID GUID
}

type VarFile interface {
	io.ReadWriteCloser
	Readdir(n int) ([]os.FileInfo, error)
	GetInodeFlags() (int, error)
	SetInodeFlags(flags int) error
}

type varfsFile struct {
	*os.File
}

// ReadVariable calls Get() on the current efivarfs backend
func ReadVariable(name string, guid GUID) (VariableAttributes, []byte, error) {
	return vars.Get(name, guid)
}

// SimpleReadVariable is like ReadVariables but takes the combined name and guid string
// of the form name-guid and returns a bytes.Reader instead of a []byte
func SimpleReadVariable(v string) (VariableAttributes, bytes.Reader, error) {
	vs := strings.SplitN(v, "-", 2)
	g, err := DecodeGUIDString(vs[1])
	if err != nil {
		return 0, *bytes.NewReader(nil), err
	}
	attrs, data, err := vars.Get(vs[0], g)
	return attrs, *bytes.NewReader(data), err
}

// WriteVariable calls Set() on the current efivarfs backend
func WriteVariable(name string, guid GUID, attrs VariableAttributes, data []byte) error {
	return maybeRetry(4, func() (bool, error) { return vars.Set(name, guid, attrs, data) })
}

// SimpleWriteVariable is like WriteVariables but takes the combined name and guid string
// of the form name-guid and returns a bytes.Buffer instead of a []byte
func SimpleWriteVariable(v string, attrs VariableAttributes, data bytes.Buffer) error {
	vs := strings.SplitN(v, "-", 2)
	g, err := DecodeGUIDString(vs[1])
	if err != nil {
		return err
	}
	_, err = vars.Set(vs[0], g, attrs, data.Bytes())
	return err
}

// DeleteVariable calls Delete() on the current efivarfs backend
func DeleteVariable(name string, guid GUID) error {
	return vars.Delete(name, guid)
}

// SimpleDeleteVariable is like DeleteVariable but takes the combined name and guid string
// of the form name-guid
func SimpleDeleteVariable(v string) error {
	vs := strings.SplitN(v, "-", 2)
	g, err := DecodeGUIDString(vs[1])
	if err != nil {
		return err
	}
	return vars.Delete(vs[0], g)
}

// ListVariables calls List() on the current efivarfs backend
func ListVariables() ([]VariableDescriptor, error) {
	return vars.List()
}

// SimpleListVariables is like ListVariables but returns a []string instead of a []VariableDescriptor
func SimpleListVariables() ([]string, error) {
	list, err := vars.List()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range list {
		out = append(out, v.Name+"-"+v.GUID.String())
	}
	return out, nil
}

func openVarfsFile(path string, flags int, perm os.FileMode) (VarFile, error) {
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return nil, err
	}
	return &varfsFile{f}, nil
}

// GetInodeFlags returns the extended attributes of a file
func (f *varfsFile) GetInodeFlags() (int, error) {
	// If I knew how unix.Getxattr works I'd use that...
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return 0, &os.PathError{Op: "ioctl", Path: f.Name(), Err: err}
	}
	return flags, nil
}

// SetInodeFlags sets the extended attributes of a file
func (f *varfsFile) SetInodeFlags(flags int) error {
	// If I knew how unix.Setxattr works I'd use that...
	err := unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, flags)
	if err != nil {
		return &os.PathError{Op: "ioctl", Path: f.Name(), Err: err}
	}
	return nil
}

func makeVarFileMutable(f VarFile) (restore func() error, err error) {
	const FS_IMMUTABLE_FL = int(0x00000010)

	flags, err := f.GetInodeFlags()
	if err != nil {
		return nil, err
	}
	if flags&FS_IMMUTABLE_FL == 0 {
		return func() error { return nil }, nil
	}

	err = f.SetInodeFlags(flags &^ FS_IMMUTABLE_FL)
	if err != nil {
		return nil, err
	}
	return func() error {
		return f.SetInodeFlags(flags)
	}, nil
}

func maybeRetry(n int, fn func() (bool, error)) error {
	for i := 1; ; i++ {
		retry, err := fn()
		switch {
		case i > n:
			return err
		case !retry:
			return err
		case err == nil:
			return nil
		}
	}
}
