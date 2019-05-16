package secrets

import (
	"errors"

	"github.com/spf13/viper"
)

// LocalSecretManager is just a struct
type LocalSecretManager struct {
	TokenMapper *Mapper
}

// CreateNewLocalSecretManager creates a new secret manager hooked up to Viper
func CreateNewLocalSecretManager(m *Mapper) *LocalSecretManager {
	return &LocalSecretManager{m}
}

// GetAppToken gets the token from Viper
func (s LocalSecretManager) GetAppToken(app, environment string) (string, error) {
	tokenName, err := s.TokenMapper.GetTokenName(app, environment)
	if err != nil {
		return "", err
	}

	token := viper.GetString("TOKEN_" + tokenName)

	if token == "" {
		return "", errors.New("token '" + tokenName + "' not found")
	}

	return token, nil
}

// GetSetting gets a setting from Viper
func (s LocalSecretManager) GetSetting(key string) (string, error) {
	setting := viper.GetString(key)

	if setting == "" {
		return "", errors.New("setting not found")
	}

	return setting, nil
}