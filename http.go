package awsconsoleauth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdmob/goamz/sts"
	"github.com/dgrijalva/jwt-go"
	"github.com/drone/config"
	"golang.org/x/oauth2"
)

var trustXForwarded = config.Bool("trust-x-forwarded", true)

var loginTimeout = config.Duration("google-login-timeout", time.Second*120)

// We reuse the Google client secret as the web secret.
var secret = googleClientSecret

// getOriginUrl returns the HTTP origin string (i.e.
// https://alice.example.com, or http://localhost:8000)
func getOriginURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if *trustXForwarded {
		scheme = r.Header.Get("X-Forwarded-Proto")
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

func getRemoteAddress(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	if *trustXForwarded {
		forwardedFor := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		remoteAddr = strings.TrimSpace(forwardedFor[len(forwardedFor)-1])
	}
	return remoteAddr
}

// GetRoot handles requests for '/' by redirecting to the Google OAuth URL.
//
// Any query string arguments are passed securely through the OAuth flow to
// /oauth2callback
func GetRoot(w http.ResponseWriter, r *http.Request) {
	state, err := generateState(r)
	if err != nil {
		log.Printf("ERROR: cannot generate token: %s", err)
		http.Error(w, "Authentication failed", 500)
		return
	}

	oauthConfig := *googleOauthConfig
	oauthConfig.RedirectURL = fmt.Sprintf("%s/oauth2callback", getOriginURL(r))
	url := oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
}

// generateState builds a JWT that we can use as /state/ across the oauth
// request to mitigate CSRF. When handling the callback we use validateState()
// to make sure that the callback request corresponds to a valid request we
// emitted.
func generateState(r *http.Request) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["ua"] = r.Header.Get("User-Agent")
	token.Claims["ra"] = getRemoteAddress(r)
	token.Claims["exp"] = time.Now().Add(*loginTimeout).Unix()
	token.Claims["query"] = r.URL.RawQuery
	state, err := token.SignedString([]byte(*secret))
	return state, err
}

// valididateState checks that the state parameter is valid and returns nil if
// so, otherwise it returns a non-nill error value. (Do not show the returned
// error to the user, it might contain security-sensitive information)
func valididateState(r *http.Request, state string) (string, error) {
	token, err := jwt.Parse(state, func(t *jwt.Token) (interface{}, error) {
		return []byte(*secret), nil
	})
	if err != nil {
		return "", err
	}

	if !token.Valid {
		// TODO(ross): this branch is never executed, I think because if the
		//   token is invalid `err` is never nil from Parse()
		return "", fmt.Errorf("Invalid Token")
	}

	if token.Claims["ra"].(string) != getRemoteAddress(r) {
		return "", fmt.Errorf("Wrong remote address. Expected %#v, got %#v",
			token.Claims["ra"].(string), getRemoteAddress(r))
	}

	if token.Claims["ua"].(string) != r.Header.Get("User-Agent") {
		return "", fmt.Errorf("Wrong user agent. Expected %#v, got %#v",
			token.Claims["ua"].(string), r.Header.Get("User-Agent"))
	}

	return token.Claims["query"].(string), nil
}

// GetCallback handles requests for '/oauth2callback' by validating the oauth
// response, determining the user's group membership, determining the user's
// AWS policy, fetching credentials and (optionally) redirecting to the console.
//
// The returned document is controlled by the `view` argument passed to the
// root URL.
//
// - if view=sh is specified, then a bash-compatible script is returned with the
//   credentials
// - if view=csh is specified, then a csh-compatible script is returned with
//   the credentials
// - if view=fish is specified, then a fish-compatible script is returned with
//   the credentials
// - otherwise we redirect to the AWS Console. If `uri` is specified it is
//   appended to the end of the aws console url.
//
// For example:
//
// - https://aws.example.com/?view=sh -> returns a bash script
//
// - https://aws.example.com/?uri=/s3/home -> redirects to https://console.aws.amazon.com/s3/home
//
func GetCallback(w http.ResponseWriter, r *http.Request) {
	oauthConfig := *googleOauthConfig
	oauthConfig.RedirectURL = fmt.Sprintf("%s/oauth2callback", getOriginURL(r))

	oauthToken, err := oauthConfig.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		log.Printf("oauth exchange failed: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	rawQuery, err := valididateState(r, r.FormValue("state"))
	if err != nil {
		log.Printf("ERROR: state: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	user, err := GetUserFromGoogleOauthToken(oauthToken.Extra("id_token").(string))
	if err != nil {
		log.Printf("failed to parse google id_token: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	groups, err := GetUserGroups(user)
	if err != nil {
		log.Printf("failed to fetch google group membership for %s: %s", user, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	policy, err := MapUserAndGroupsToPolicy(user, groups)
	if err != nil {
		log.Printf("failed to determine policy for %s: %s", user, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if policy == nil {
		log.Printf("no matching policy for %s", user)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	credentials, err := GetCredentials(user, policy.Policy, time.Second*43200)
	if err != nil {
		log.Printf("failed to get credentials for %s: %s", user, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		log.Printf("ERROR: parse query: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	fmt.Printf("login %s from %s with policy %s key %s\n", user, getRemoteAddress(r),
		policy.Name, credentials.AccessKeyId)
	RespondWithCredentials(w, r, credentials, query)
}

// RespondWithCredentials response to the oauth callback request based on the
// query parameters and the specified credentials.
func RespondWithCredentials(w http.ResponseWriter, r *http.Request,
	credentials *sts.Credentials, query url.Values) {
	if query.Get("action") == "key" || query.Get("view") == "sh" {
		w.Header().Set("Content-type", "text-plain")
		fmt.Fprintf(w, "# expires %s\n", credentials.Expiration)
		fmt.Fprintf(w, "export AWS_ACCESS_KEY_ID=\"%s\"\n",
			credentials.AccessKeyId)
		fmt.Fprintf(w, "export AWS_SECRET_ACCESS_KEY=\"%s\"\n",
			credentials.SecretAccessKey)
		fmt.Fprintf(w, "export AWS_SESSION_TOKEN=\"%s\"\n",
			credentials.SessionToken)
		return
	}

	if query.Get("view") == "csh" {
		w.Header().Set("Content-type", "text-plain")
		fmt.Fprintf(w, "# expires %s\n", credentials.Expiration)
		fmt.Fprintf(w, "setenv AWS_ACCESS_KEY_ID \"%s\"\n", credentials.AccessKeyId)
		fmt.Fprintf(w, "setenv AWS_SECRET_ACCESS_KEY \"%s\"\n", credentials.SecretAccessKey)
		fmt.Fprintf(w, "setenv AWS_SESSION_TOKEN \"%s\"\n", credentials.SessionToken)
		return
	}

	if query.Get("view") == "fish" {
		w.Header().Set("Content-type", "text-plain")
		fmt.Fprintf(w, "# expires %s\n", credentials.Expiration)
		fmt.Fprintf(w, "set -x AWS_ACCESS_KEY_ID \"%s\"\n", credentials.AccessKeyId)
		fmt.Fprintf(w, "set -x AWS_SECRET_ACCESS_KEY \"%s\"\n", credentials.SecretAccessKey)
		fmt.Fprintf(w, "set -x AWS_SESSION_TOKEN \"%s\"\n", credentials.SessionToken)
		return
	}

	redirectURL, err := GetAWSConsoleURL(credentials, query.Get("uri"))
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Initialize sets up the web server and binds the URI patterns for the
// authorization service.
func Initialize() error {
	if err := LoadConfig(); err != nil {
		return fmt.Errorf("LoadConfig: %s", err)
	}

	if err := InitializeGoogleLogin(); err != nil {
		return fmt.Errorf("InitializeGoogleLogin: %s", err)

	}

	if err := InitializeAWS(); err != nil {
		return fmt.Errorf("InitializeAWS: %s", err)
	}

	http.HandleFunc("/", GetRoot)
	http.HandleFunc("/oauth2callback", GetCallback)
	return nil
}
