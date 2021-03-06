package awsconsoleauth

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/drone/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleClientID = config.String("google-client-id", "")
var googleClientSecret = config.String("google-client-secret", "")
var googleDomain = config.String("google-domain", "")

var googleOauthConfig = &oauth2.Config{
	Scopes:   []string{"email"},
	Endpoint: google.Endpoint,
}

var googleJWTSigningKeys = map[string]interface{}{}

func updateGoogleJWTSigningKeys() error {
	// Fetch the google keys for oauth
	googleCertsResponse, err := http.Get("https://www.googleapis.com/oauth2/v1/certs")
	if err != nil {
		return err
	}
	if err := json.NewDecoder(googleCertsResponse.Body).Decode(&googleJWTSigningKeys); err != nil {
		return err
	}
	return nil
}

// InitializeGoogleLogin sets up access to the Google login service
func InitializeGoogleLogin() error {
	if err := updateGoogleJWTSigningKeys(); err != nil {
		return nil
	}

	// keep the JWT signing keys up to date by polling once per hour
	go func() {
		time.Sleep(60 * time.Minute)
		for {
			if err := updateGoogleJWTSigningKeys(); err != nil {
				log.Printf("Google JWT signing keys: %s", err)
				time.Sleep(time.Minute)
				continue
			}
			log.Printf("updates google JWT signing keys")
			time.Sleep(60 * time.Minute)
		}
	}()

	// Configure OAuth
	googleOauthConfig.ClientID = *googleClientID
	googleOauthConfig.ClientSecret = *googleClientSecret
	if *googleDomain != "" {
		googleOauthConfig.Endpoint.AuthURL += fmt.Sprintf("?hd=%s", *googleDomain)
	}

	return nil
}

// GetUserFromGoogleOauthToken returns a user name (email address) from the
// provided ID token which we receive in the OAuth response. This function
// validates that the idToken is signed by a valid JWT public key.
func GetUserFromGoogleOauthToken(idToken string) (string, error) {
	token, err := jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		keyString, ok := googleJWTSigningKeys[t.Header["kid"].(string)]
		if !ok {
			return nil, fmt.Errorf("Unknown key in token")
		}
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(keyString.(string)))
		if err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil {
		return "", err
	}

	if *googleDomain != "" {
		if token.Claims["hd"].(string) != *googleDomain {
			return "", fmt.Errorf("expected domain %s, got domain %s",
				*googleDomain, token.Claims["hd"].(string))
		}
	}
	return token.Claims["email"].(string), nil
}
