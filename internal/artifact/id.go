package artifact

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const randomIDBytes = 8

// NewID returns a filesystem-safe run identifier from a UTC timestamp and
// cryptographically random bytes. Tests pass a deterministic reader.
func NewID(now time.Time, random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	var nonce [randomIDBytes]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", now.UTC().Format("20060102T150405Z"), hex.EncodeToString(nonce[:])), nil
}

func ValidID(id string) bool {
	if id == "" || id != filepath.Base(id) || strings.Contains(id, "..") {
		return false
	}
	for _, r := range id {
		if r != '-' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
