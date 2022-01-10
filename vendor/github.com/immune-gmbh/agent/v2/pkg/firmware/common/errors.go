package common

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/immune-gmbh/agent/v2/pkg/api"
)

type FirmwareError struct {
	Code  api.FirmwareError
	Cause error
}

func Error(code api.FirmwareError, cause error) error {
	return &FirmwareError{Code: code, Cause: cause}
}

func ErrorNoPermission(cause error) error {
	return &FirmwareError{Code: api.NoPermission, Cause: cause}
}

func ErrorNoResponse(cause error) error {
	return &FirmwareError{Code: api.NoResponse, Cause: cause}
}

func (e *FirmwareError) Error() string {
	return fmt.Sprintf("firmware error code %s, cause: %v", e.Code, e.Cause)
}

func (e *FirmwareError) Unwrap() error {
	return e.Cause
}

// MapFSErrors maps fs, os and some syscall package error types to firmware errors
func MapFSErrors(err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, os.ErrPermission) {
		return ErrorNoPermission(err)
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrorNoResponse(err)
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == syscall.EACCES || errno == syscall.EPERM {
			return ErrorNoPermission(err)
		}
		// go internally maps windows file not exist errors to ENOENT so this is cross platform
		if errno == syscall.ENOENT || errno.Timeout() {
			return ErrorNoResponse(err)
		}
	}
	return err
}

func ServeApiError(err error) api.FirmwareError {
	var srvErr *FirmwareError

	if errors.As(err, &srvErr) {
		return srvErr.Code
	}

	return api.UnknownError
}
