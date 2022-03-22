package security

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/kiwicom/iam/internal/security/secrets"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/viper"
	"google.golang.org/api/idtoken"
)

var errUnauthorised = errors.New("incorrect token")
var audienceVar = "AUDIENCE" // this fails hard without audience
var gitlabJWKVar = "GITLAB_JWK_URL"

// VerifyToken accepts a token and a service struct and verifies if this token is accepted.
func VerifyToken(secretManager secrets.SecretManager, requestToken string) error {
	// check for token presence
	if requestToken == "" {
		return errUnauthorised
	}
	//log.Println("Is a token")
	log.Println(requestToken)

	// check hardcoded
	exists := secretManager.DoesTokenExist(requestToken)
	if exists {
		// log.Println("Valid VAULT token")
		return nil
	}
	//log.Println("No entry in vault")

	// try to validate as JWT
	// try to validate as google IDToken (lib by google, expecting great support in time)
	payload, err := idtoken.Validate(context.Background(), requestToken, viper.GetString(audienceVar))
	if err == nil { // token is valid
		// check whether the address is allowed
		if str, ok := payload.Claims["email"].(string); ok {
			if secretManager.IsGoogleIDInList(str) {
				// log.Println("Valid JWT")
				return nil
			}
		}
		//else the email is missing, so the token is broken, so we do nothing.
	}
	//log.Println("Not a google ID JWT")
	// try to validate as gitlab-signed JWT
	err = ValidateGitlabToken(requestToken, secretManager)
	//log.Println("Valid Gitlab")
	return err
}

// ValidateGitlabToken validates gitlab token.
func ValidateGitlabToken(requestToken string, secretManager secrets.SecretManager) error {
	gitlabJWKUrl := viper.GetString(gitlabJWKVar)
	set, err := jwk.Fetch(context.Background(), gitlabJWKUrl)
	if err != nil {
		//return err
		return errUnauthorised
	}
	//log.Println("Got keys")
	parsedToken, err := jwt.Parse(
		[]byte(requestToken),
		jwt.WithKeySet(set),
	)
	if err != nil {
		//return err
		return errUnauthorised
	}
	//log.Println("Token signature valid")
	exp := parsedToken.Expiration()
	if exp.Before(time.Now()) {
		//log.Println("Token expired")
		return errUnauthorised
	}
	//log.Println("Token expiration ok")
	projID, b := parsedToken.Get("project_id")
	if !b {
		return errUnauthorised
	}
	ref, b := parsedToken.Get("ref")
	if !b {
		return errUnauthorised
	}
	//log.Println("Token has claims")
	claim := strings.Join([]string{projID.(string), ref.(string)}, "/")
	if secretManager.IsGitlabClaimInList(claim) {
		//log.Println("Valid gitlab JWT")
		return nil
	}
	return errUnauthorised
}
