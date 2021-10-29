// This code is a somewhat simplified and changed up version of
// github.com/canonical/go-efilib credits go their authors.
// It allows interaction with the efivarfs via u-root which means
// both read and write support.

package efivarfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	if !probeEfivarfs() {
		return
	}
}

// EfiVarFs is the path to the efivarfs mount point
const EfiVarFs = "/sys/firmware/efi/efivars/"

var vars varsBackend = varfsBackend{}

type varsBackend interface {
	Get(name string, guid GUID) (VariableAttributes, []byte, error)
	Set(name string, guid GUID, attrs VariableAttributes, data []byte) (bool, error)
	Delete(name string, guid GUID) error
	List() ([]VariableDescriptor, error)
}

type varfsBackend struct{}

// Get reads the contents of an efivar if it exists and has the necessary permission
func (v varfsBackend) Get(name string, guid GUID) (VariableAttributes, []byte, error) {
	path := filepath.Join(EfiVarFs, fmt.Sprintf("%s-%s", name, guid))
	f, err := openVarfsFile(path, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
		return 0, nil, ErrVarNotExist
	case os.IsPermission(err):
		return 0, nil, ErrVarPermission
	case err != nil:
		return 0, nil, err
	}
	defer f.Close()

	var attrs VariableAttributes
	err = binary.Read(f, binary.LittleEndian, &attrs)
	if err != nil {
		if err == io.EOF {
			return 0, nil, ErrVarNotExist
		}
		return 0, nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return 0, nil, err
	}
	return attrs, data, nil
}

// Set modifies a given efivar with the provided contents
func (v varfsBackend) Set(name string, guid GUID, attrs VariableAttributes, data []byte) (bool, error) {
	path := filepath.Join(EfiVarFs, fmt.Sprintf("%s-%s", name, guid))
	flags := os.O_WRONLY | os.O_CREATE
	if attrs&AttributeAppendWrite != 0 {
		flags |= os.O_APPEND
	}

	read, err := openVarfsFile(path, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
	case os.IsPermission(err):
		return false, ErrVarPermission
	case err != nil:
		return false, err
	default:
		defer read.Close()

		restoreImmutable, err := makeVarFileMutable(read)
		switch {
		case os.IsPermission(err):
			return false, ErrVarPermission
		case err != nil:
			return false, err
		}
		defer restoreImmutable()
	}

	write, err := openVarfsFile(path, flags, 0644)
	switch {
	case os.IsPermission(err):
		pe, ok := err.(*os.PathError)
		if !ok {
			return false, err
		}
		if pe.Err == syscall.EACCES {
			// open will fail with EACCES if we lack the privileges
			// to write to the file or the parent directory in the
			// case where we need to create a new file. Don't retry
			// in this case.
			return false, ErrVarPermission
		}

		// open will fail with EPERM if the file exists but we can't
		// write to it because it is immutable. This might happen as a
		// result of a race with another process that might have been
		// writing to the variable or may have deleted and recreated
		// it, making the underlying inode immutable again. Retry in
		// this case.
		return true, ErrVarPermission
	case err != nil:
		return false, err
	}
	defer write.Close()

	var buf bytes.Buffer
	err = binary.Write(&buf, binary.LittleEndian, attrs)
	if err != nil {
		return false, err
	}
	for len(data)%8 != 0 {
		data = append(data, 0)
	}
	size, err := buf.Write(data)
	if err != nil {
		return false, err
	}
	if (size-4)%8 == 0 {
		return false, fmt.Errorf("data misaligned")
	}
	_, err = buf.WriteTo(write)
	if err != nil {
		return false, err
	}
	return false, nil
}

// Delete makes the specified EFI var mutable and then deletes it
func (v varfsBackend) Delete(name string, guid GUID) error {
	path := filepath.Join(EfiVarFs, fmt.Sprintf("%s-%s", name, guid))
	f, err := openVarfsFile(path, os.O_WRONLY, 0)
	switch {
	case os.IsNotExist(err):
		return ErrVarNotExist
	case os.IsPermission(err):
		return ErrVarPermission
	case err != nil:
		return err
	default:
		_, err := makeVarFileMutable(f)
		switch {
		case os.IsPermission(err):
			return ErrVarPermission
		case err != nil:
			return err
		default:
			f.Close()
		}
	}
	return os.Remove(path)
}

// List returns the VariableDescriptor for each efivar in the system
func (v varfsBackend) List() ([]VariableDescriptor, error) {
	const guidLength = 36
	f, err := openVarfsFile(EfiVarFs, os.O_RDONLY, 0)
	switch {
	case os.IsNotExist(err):
		return nil, ErrVarNotExist
	case os.IsPermission(err):
		return nil, ErrVarPermission
	case err != nil:
		return nil, err
	}
	defer f.Close()

	dirents, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}
	var entries []VariableDescriptor
	for _, dirent := range dirents {
		if !dirent.Mode().IsRegular() {
			// Skip non-regular files
			continue
		}
		if len(dirent.Name()) < guidLength+1 {
			// Skip files with a basename that isn't long enough
			// to contain a GUID and a hyphen
			continue
		}
		if dirent.Name()[len(dirent.Name())-guidLength-1] != '-' {
			// Skip files where the basename doesn't contain a
			// hyphen between the name and GUID
			continue
		}
		if dirent.Size() == 0 {
			// Skip files with zero size. These are variables that
			// have been deleted by writing an empty payload
			continue
		}

		name := dirent.Name()[:len(dirent.Name())-guidLength-1]
		guid, err := DecodeGUIDString(dirent.Name()[len(name)+1:])
		if err != nil {
			continue
		}

		entries = append(entries, VariableDescriptor{Name: name, GUID: guid})
	}

	sort.Slice(entries, func(i, j int) bool {
		return fmt.Sprintf("%s-%v", entries[i].Name, entries[i].GUID) < fmt.Sprintf("%s-%v", entries[j].Name, entries[j].GUID)
	})
	return entries, nil
}

func probeEfivarfs() bool {
	var stat unix.Statfs_t
	err := unix.Statfs(EfiVarFs, &stat)
	if err != nil {
		return false
	}
	if uint(stat.Type) != uint(unix.EFIVARFS_MAGIC) {
		return false
	}
	return true
}
