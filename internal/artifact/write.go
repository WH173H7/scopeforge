package artifact

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/WH173H7/scopeforge/internal/model"
	"github.com/WH173H7/scopeforge/internal/render"
)

const (
	dirPermission  fs.FileMode = 0o700
	filePermission fs.FileMode = 0o600
)

var (
	// ErrExists reports that the destination artifact already exists.
	ErrExists = errors.New("run artifact already exists")
	// ErrInvalidID reports that the run ID cannot be used as a filename.
	ErrInvalidID = errors.New("run ID is invalid")
	// ErrInvalidDir reports that the save directory cannot be used.
	ErrInvalidDir = errors.New("save directory is invalid")
)

// Write serializes a completed run with the canonical JSON encoder into dir.
// It creates dir with owner-only permissions when the directory does not yet
// exist, and does not chmod a pre-existing directory.
//
// The destination is created with O_EXCL so an existing artifact is never
// replaced. A detected write, sync, or close failure removes the incomplete
// file where practical. This is not crash-atomic persistence.
func Write(dir string, run model.Run) error {
	if dir == "" {
		return ErrInvalidDir
	}
	if !validID(run.ID) {
		return ErrInvalidID
	}

	if err := ensureDir(dir); err != nil {
		return err
	}

	destination := filepath.Join(dir, run.ID+".json")
	if filepath.Dir(destination) != filepath.Clean(dir) {
		return ErrInvalidID
	}

	payload, err := encodedRun(run)
	if err != nil {
		return err
	}
	return writeExclusive(destination, payload)
}

func encodedRun(run model.Run) ([]byte, error) {
	var output bytes.Buffer
	if err := render.RunJSON(&output, run); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func ensureDir(dir string) error {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, dirPermission); err != nil {
			return err
		}
		if runtime.GOOS != "windows" {
			_ = os.Chmod(dir, dirPermission)
		}
		return nil
	case err != nil:
		return err
	case !info.IsDir():
		return ErrInvalidDir
	default:
		return nil
	}
}

func writeExclusive(path string, payload []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePermission)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if runtime.GOOS != "windows" {
		_ = file.Chmod(filePermission)
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}
