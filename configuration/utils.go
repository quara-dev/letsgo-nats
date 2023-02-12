package configuration

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/net/idna"
)

// Sanitize a domain name.
//
// The return name can safely be used as a filename.
func sanitizeDomain(domain string) (string, error) {
	safe, err := idna.ToASCII(strings.ReplaceAll(domain, "*", "_"))
	if err != nil {
		return safe, err
	}
	return safe, nil
}

// Get an environment variable
//
// A fallback value must be provided as argument.
// If environment variable is not defined, fallback value
// is used instead.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// Check if a file exists.
//
// Return `true` when file exists, else `false`.
func fileExists(path string) bool {
	// Check if a file exists
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}
