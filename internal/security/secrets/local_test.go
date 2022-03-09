package secrets

import (
	"os"
	"testing"
	//"fmt"

	cfg "github.com/kiwicom/iam/configs"
	"github.com/stretchr/testify/assert"
)

func load_configs() {
	cfg.InitEnv()

	var (
		iamConfig     cfg.ServiceConfig
		oktaConfig    cfg.OktaConfig
		storageConfig cfg.StorageConfig
		datadogConfig cfg.DatadogConfig
		sentryConfig  cfg.SentryConfig
		secretsConfig cfg.SecretsConfig
	)

	// If there is an error loading the envs kill the app, as nothing will work without them.
	if err := cfg.LoadConfigs(&iamConfig, &oktaConfig, &storageConfig, &datadogConfig, &sentryConfig, &secretsConfig); err != nil {
		panic(err)
	}
}

func TestLocalDoesTokenExist(t *testing.T) {
	os.Setenv("TOKEN", "tokenval1")
	load_configs()
	tests := map[string]bool{
		"tokenval1": true,
		"tokenval2": false,
	}
	lm := CreateNewLocalSecretManager()
	for test, expected := range tests {
		assert.Equal(t, expected, lm.DoesTokenExist(test))
	}
}

func TestLocalIsGoogleIDInList(t *testing.T) {
	os.Setenv("GOOGLEID_ALLOWLIST", "email1@gserviceaccount.com email2@gserviceaccount.com")
	load_configs()
	tests := map[string]bool{
		"email1@gserviceaccount.com": true,
		"email2@gserviceaccount.com": true,
		"email3@gserviceaccount.com": false,
	}
	lm := CreateNewLocalSecretManager()
	for test, expected := range tests {
		assert.Equal(t, expected, lm.IsGoogleIDInList(test))
	}
}

func TestLocalIsGitlabClaimInList(t *testing.T) {
	os.Setenv("GITLABCLAIM_ALLOWLIST", "1/master 2/master 3/not-master")
	load_configs()
	tests := map[string]bool{
		"1/master":     true,
		"2/master":     true,
		"3/master":     false,
		"3/not-master": true,
		"4/master":     false,
		"2/not-master": false,
	}
	lm := CreateNewLocalSecretManager()
	for test, expected := range tests {
		assert.Equal(t, expected, lm.IsGitlabClaimInList(test))
	}
}

func TestLocalGetSetting(t *testing.T) {
	tests_happy := map[string]string{
		"LABEL1": "setting1",
		"LABEL2": "setting2",
	}
	for test, expected := range tests_happy {
		os.Setenv(test, expected)
	}
	load_configs()
	lm := CreateNewLocalSecretManager()
	for test, expected := range tests_happy {
		res, err := lm.GetSetting(test)
		assert.Equal(t, expected, res)
		assert.NoError(t, err)
	}

	tests_unhappy := []string{
		"LABEL3",
	}
	for test := range tests_unhappy {
		_, err := lm.GetSetting(tests_unhappy[test])
		assert.Error(t, err)
	}
}
