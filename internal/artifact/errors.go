package artifact

import (
	"errors"
	"io/fs"
)

var (
	// ErrExists reports that the destination artifact already exists.
	ErrExists = errors.New("run artifact already exists")
	// ErrInvalidID reports that the run ID cannot be used as a filename.
	ErrInvalidID = errors.New("run ID is invalid")
	// ErrInvalidDir reports that the save directory cannot be used.
	ErrInvalidDir = errors.New("save directory is invalid")
	// ErrNotFound reports that the requested artifact file does not exist.
	ErrNotFound = errors.New("run artifact not found")
	// ErrTooLarge reports that the artifact exceeds MaxBytes.
	ErrTooLarge = errors.New("run artifact is too large")
	// ErrInvalid reports that the artifact is not a valid schema version 1 document.
	ErrInvalid = errors.New("run artifact is invalid")
	// ErrUnsupportedSchema reports a missing, empty, or unknown schema_version.
	ErrUnsupportedSchema = errors.New("run artifact schema is unsupported")
	// ErrIDMismatch reports that the document ID does not match the requested ID.
	ErrIDMismatch = errors.New("run artifact ID does not match")
	// ErrReadFailed reports an unexpected filesystem read failure.
	ErrReadFailed = errors.New("could not read run artifact")
)

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
