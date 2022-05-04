package secrets

import (
	"errors"

	"github.com/spf13/viper"
)

// LocalSecretManager is just a struct.
type LocalSecretManager struct{}

// CreateNewLocalSecretManager creates a new secret manager hooked up to Viper.
func CreateNewLocalSecretManager() *LocalSecretManager {
	return &LocalSecretManager{}
}

// DoesTokenExist checks if a token is present in the secret manager.
func (s LocalSecretManager) DoesTokenExist(reqToken string) bool {
	token := viper.GetString("TOKEN")

	return reqToken == token
}

// IsGoogleIDInList checks for a presence of google_id (email) in the allowlist
func (s LocalSecretManager) IsGoogleIDInList(email string) bool {
	googleAllowlistVar := "GOOGLEID_ALLOWLIST"
	googleIDAllowedList := viper.GetStringSlice(googleAllowlistVar)
	for _, val := range googleIDAllowedList {
		if val == email {
			return true
		}
	}
	return false
}

// GetAudiences returns a list of configured audiences
func (s LocalSecretManager) GetAudiences() []string {
	googleAudienceListVar := "AUDIENCE"
	googleAudienceList := viper.GetStringSlice(googleAudienceListVar)
	return googleAudienceList
}

// IsGitlabClaimInList checks for a presence of tuple of proj_id/branch in the allowlist
func (s LocalSecretManager) IsGitlabClaimInList(claim string) bool {
	gitlabAllowlistVar := "GITLABCLAIM_ALLOWLIST"
	gitlabClaimAllowedList := viper.GetStringSlice(gitlabAllowlistVar)
	for _, val := range gitlabClaimAllowedList {
		if val == claim {
			return true
		}
	}
	return false
}

// GetSetting gets a setting from Viper.
func (s LocalSecretManager) GetSetting(key string) (string, error) {
	setting := viper.GetString(key)

	if setting == "" {
		return "", errors.New("setting not found")
	}

	return setting, nil
}
