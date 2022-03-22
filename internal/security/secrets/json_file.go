package secrets

import (
	"errors"
	"io/ioutil"
	"log"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

// Secrets represents the JSON file structure.
type Secrets struct {
	Settings     map[string]string            `json:"settings"`
	TokenMap     map[string]map[string]string `json:"tokens"`
	GoogleIDs    []string                     `json:"google_ids"`
	GitlabClaims []string                     `json:"gitlab_claims"`
	Audiences    []string                     `json:"audiences"`
}

// JSONFileManager holds a local copy of all secrets (settings & S2S tokens).
type JSONFileManager struct {
	paths        []string
	settings     map[string]string
	tokens       map[string]bool
	googleIds    map[string]bool
	gitlabClaims map[string]bool
	audiences    map[string]bool
}

// CreateNewJSONFileManager creates a new secret manager hooked up to Viper.
func CreateNewJSONFileManager(path string) (*JSONFileManager, error) {
	paths := strings.Split(path, ":")
	// try if you can read the file, if not, return err.
	for _, p := range paths {
		_, err := ioutil.ReadFile(p)
		if err != nil {
			return nil, err
		}
		log.Println("Using JSON secret file at:", p)
	}

	return &JSONFileManager{
		paths:        paths,
		settings:     nil,
		tokens:       nil,
		googleIds:    nil,
		gitlabClaims: nil,
		audiences:    nil,
	}, nil
}

// SyncSecrets syncs all the available tokens from env and saves them to local state.
func (s *JSONFileManager) SyncSecrets() error {
	// read the files again to actually sync stuff
	newSettings := make(map[string]string)
	newTokens := make(map[string]bool)
	newGoogleIds := make(map[string]bool)
	newGitlabClaims := make(map[string]bool)
	newAudiences := make(map[string]bool)
	for _, path := range s.paths {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		var secrets Secrets

		if err := json.Unmarshal(data, &secrets); err != nil {
			return err
		}

		for _, app := range secrets.TokenMap {
			for _, token := range app {
				newTokens[token] = true
			}
		}

		for k, v := range secrets.Settings {
			if _, ok := newSettings[k]; ok {
				log.Printf("[WARN] Overriding setting %s original %s to %s!", k, newSettings[k], v)
			}
			newSettings[k] = v
		}
		for gid := range secrets.GoogleIDs {
			newGoogleIds[secrets.GoogleIDs[gid]] = true
		}
		for gc := range secrets.GitlabClaims {
			newGitlabClaims[secrets.GitlabClaims[gc]] = true
		}
		for aud := range secrets.Audiences {
			newAudiences[secrets.Audiences[aud]] = true
		}

	}
	s.settings = newSettings
	s.tokens = newTokens
	s.googleIds = newGoogleIds
	s.gitlabClaims = newGitlabClaims
	s.audiences = newAudiences
	log.Printf("Synced %v settings, %v tokens, %v Google IDs and %v GitLab claims.", len(s.settings), len(s.tokens), len(s.googleIds), len(s.gitlabClaims))
	return nil
}

// DoesTokenExist checks if a token is present in the secret manager.
func (s JSONFileManager) DoesTokenExist(reqToken string) bool {
	return s.tokens[reqToken]
}

// IsGoogleIDInList checks for a presence of google_id (email) in the allowlist
func (s JSONFileManager) IsGoogleIDInList(email string) bool {
	return s.googleIds[email]
}

// IsGitlabClaimInList checks for a presence of tuple of proj_id/branch in the allowlist
func (s JSONFileManager) IsGitlabClaimInList(claim string) bool {
	return s.gitlabClaims[claim]
}

// GetAudiences returns a list of configured audiences
func (s JSONFileManager) GetAudiences() []string {
	count := 0
	for _, val := range s.audiences {
		if val {
			count++
		}
	}
	audiences := make([]string, count)
	count = 0
	for key, val := range s.audiences {
		if val {
			audiences[count] = key
			count++
		}
	}
	return audiences
}

// GetSetting gets a setting from the secret manager.
func (s JSONFileManager) GetSetting(key string) (string, error) {
	data := s.settings[key]

	if data == "" {
		return "", errors.New("key '" + key + "' not found in SecretManager")
	}

	return data, nil
}
