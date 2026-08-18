package artifact

import (
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/WH173H7/scopeforge/internal/model"
)

// Read loads one schema version 1 run artifact from dir for id.
// It is read-only: it does not modify, chmod, rename, or rewrite the file,
// and it performs no network activity.
func Read(dir, id string) (model.Run, error) {
	path, err := artifactPath(dir, id)
	if err != nil {
		return model.Run{}, err
	}

	info, err := os.Lstat(path)
	switch {
	case isNotExist(err):
		return model.Run{}, ErrNotFound
	case err != nil:
		return model.Run{}, ErrReadFailed
	case info.Mode()&os.ModeSymlink != 0:
		return model.Run{}, ErrInvalid
	case !info.Mode().IsRegular():
		return model.Run{}, ErrInvalid
	case info.Size() > MaxBytes:
		return model.Run{}, ErrTooLarge
	}

	file, err := os.Open(path)
	if err != nil {
		if isNotExist(err) {
			return model.Run{}, ErrNotFound
		}
		return model.Run{}, ErrReadFailed
	}
	defer file.Close()

	payload, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if err != nil {
		return model.Run{}, ErrReadFailed
	}
	if int64(len(payload)) > MaxBytes {
		return model.Run{}, ErrTooLarge
	}

	var document Document
	if err := json.Unmarshal(payload, &document); err != nil {
		return model.Run{}, ErrInvalid
	}
	if err := validateDocument(document, id); err != nil {
		return model.Run{}, err
	}
	run, err := runFromDocument(document)
	if err != nil {
		if errors.Is(err, ErrInvalid) {
			return model.Run{}, err
		}
		return model.Run{}, ErrInvalid
	}
	return run, nil
}
