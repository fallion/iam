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
}

// JSONFileManager holds a local copy of all secrets (settings & S2S tokens).
type JSONFileManager struct {
	paths        []string
	settings     map[string]string
	tokens       map[string]bool
	googleIds    map[string]bool
	gitlabClaims map[string]bool
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
		tokens:       make(map[string]bool),
		googleIds:    make(map[string]bool),
		gitlabClaims: make(map[string]bool),
	}, nil
}

// SyncSecrets syncs all the available tokens from env and saves them to local state.
func (s *JSONFileManager) SyncSecrets() error {
	// read the files again to actually sync stuff
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
				s.tokens[token] = true
			}
		}

		if s.settings == nil {
			s.settings = secrets.Settings
		} else {
			for k, v := range secrets.Settings {
				s.settings[k] = v
			}
		}
		for gid := range secrets.GoogleIDs {
			s.googleIds[secrets.GoogleIDs[gid]] = true
		}
		for gc := range secrets.GitlabClaims {
			s.gitlabClaims[secrets.GitlabClaims[gc]] = true
		}

	}
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

// GetSetting gets a setting from the secret manager.
func (s JSONFileManager) GetSetting(key string) (string, error) {
	data := s.settings[key]

	if data == "" {
		return "", errors.New("key '" + key + "' not found in SecretManager")
	}

	return data, nil
}