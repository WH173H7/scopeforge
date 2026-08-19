package artifact

import (
	"path/filepath"
)

func artifactPath(dir, id string) (string, error) {
	if dir == "" {
		return "", ErrInvalidDir
	}
	if !ValidID(id) {
		return "", ErrInvalidID
	}
	destination := filepath.Join(dir, id+".json")
	if filepath.Dir(destination) != filepath.Clean(dir) {
		return "", ErrInvalidID
	}
	return destination, nil
}
