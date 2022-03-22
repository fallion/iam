package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetToken(t *testing.T) {
	tests := map[string]struct {
		headers  map[string]string
		expToken string
		errors   bool
	}{
		"Bearer token": {
			headers:  map[string]string{"Authorization": "Bearer token"},
			expToken: "token",
			errors:   false,
		},
		"token": {
			headers:  map[string]string{"Authorization": "token"},
			expToken: "",
			errors:   true,
		},
		"Bearer Bearer token": {
			headers:  map[string]string{"Authorization": "Bearer Bearer token"},
			expToken: "Bearer token",
			errors:   false,
		},
		"Bearer": {
			headers:  map[string]string{"Authorization": "Bearer"},
			expToken: "",
			errors:   false,
		},
		"unexpected Bearer token": {
			headers:  map[string]string{"Authorization": "unexpected Bearer token"},
			expToken: "",
			errors:   true,
		},
	}

	for _, test := range tests {
		actual, err := GetToken(test.headers)
		assert.Equal(t, test.expToken, actual)

		if test.errors {
			assert.Error(t, err)
		}
	}
}
