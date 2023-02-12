package configuration

import (
	"os"
	"path/filepath"
	"testing"
)

// Test that domain names are sanitized into valid filenames
func TestSanitizeDomainWithWildcard(t *testing.T) {
	got, err := sanitizeDomain("*.example.com")
	if err != nil {
		t.Errorf(err.Error())
	}
	want := "_.example.com"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that domain names are sanitized into valid filenames
func TestSanitizeDomainSimple(t *testing.T) {
	got, err := sanitizeDomain("example.com")
	if err != nil {
		t.Errorf(err.Error())
	}
	want := "example.com"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that getEnv funcion can return the fallback value
func TestGetEnvReturnsFallback(t *testing.T) {
	got := getEnv("test-var", "default")
	want := "default"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that getEnv function can return the value from environment variable
func TestGetEnvReturnsValue(t *testing.T) {
	t.Setenv("test-var", "value")
	got := getEnv("test-var", "default")
	want := "value"
	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}
}

// Test that fileExists function behaves as expected
func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "test.txt")
	if fileExists(file) != false {
		t.Errorf("File does not exist but fileExists returned true")
	}
	os.WriteFile(file, []byte{}, 0o600)
	if fileExists(file) != true {
		t.Errorf("File exists but fileExists returned false")
	}
}
