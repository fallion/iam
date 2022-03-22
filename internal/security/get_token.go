package security

import (
	"errors"
	"strings"
)

// GetToken extracts token from Bearer scheme.
func GetToken(headers map[string]string) (string, error) {
	token := strings.SplitN(headers["Authorization"], "Bearer", 2)

	if len(token) == 2 && token[0] == "" {
		return strings.TrimSpace(token[1]), nil
	}

	if headers["X-Goog-IAP-JWT-Assertion"] != "" {
		return headers["X-Goog-IAP-JWT-Assertion"], nil
	}

	return "", errors.New("invalid auth scheme")
}
