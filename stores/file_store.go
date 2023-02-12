package stores

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

// File store implementation to fetch token from file
type FileStore struct{}

func (s *FileStore) GetToken(path string) (string, error) {
	// Read file
	rawToken, err := ioutil.ReadFile(path)
	// Or return an error
	if err != nil {
		return "", err
	}
	// Convert to string and strip line break
	token := strings.TrimSuffix(string(rawToken), "\n")
	// Check that token is not empty
	if token == "" {
		return "", errors.New(fmt.Sprintf("Invalid token found in %s", path))
	}
	// Return token
	return token, nil
}
