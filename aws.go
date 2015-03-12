package awsconsoleauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdmob/goamz/aws"
	"github.com/crowdmob/goamz/sts"
	"github.com/drone/config"
)

var awsRegion = config.String("aws-region", "")

var awsAccessKey = config.String("aws-access-key-id", "")
var awsSecretKey = config.String("aws-secret-access-key", "")

var awsAuth aws.Auth

// InitializeAWS sets up access to the AWS Simple Token Service
func InitializeAWS() error {
	if *awsRegion == "" {
		*awsRegion = aws.InstanceRegion()
		if *awsRegion == "unknown" {
			*awsRegion = "us-east-1"
		}
	}

	if *awsAccessKey == "" || *awsSecretKey == "" {
		return fmt.Errorf("you must specify aws-access-key-id and " +
			"aws-secret-access-key in the config file or " +
			"AWSAUTHD_AWS_ACCESS_KEY_ID and AWSAUTHD_AWS_SECRET_ACCESS_KEY in " +
			"the environment. These must be regular permanent credentials, not " +
			"temporary or instance credentials.")
	}

	maybeAWSAuth := aws.Auth{
		AccessKey: *awsAccessKey,
		SecretKey: *awsSecretKey,
	}
	stsConnection := sts.New(maybeAWSAuth, aws.GetRegion(*awsRegion))
	_, err := stsConnection.GetFederationToken("snakeoil", "", 900)
	if err != nil {
		return fmt.Errorf("Your credentials don't work to call "+
			"GetFederationToken(). You must specify aws-access-key-id and "+
			"aws-secret-access-key in the config file or "+
			"AWSAUTHD_AWS_ACCESS_KEY_ID and AWSAUTHD_AWS_SECRET_ACCESS_KEY in "+
			"the environment. These must be regular permanent credentials, not "+
			"temporary or instance credentials. (err=%s)", err)
	}

	// If GetFederationToken worked then we are good to go.
	awsAuth = maybeAWSAuth
	return nil
}

// GetCredentials fetches credentials for the specified user and policy.
func GetCredentials(user string, policyString string,
	tokenLifetime time.Duration) (*sts.Credentials, error) {
	stsConnection := sts.New(awsAuth, aws.GetRegion(*awsRegion))
	getTokenResult, err := stsConnection.GetFederationToken(user, policyString,
		int(tokenLifetime.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("GetFederationToken: %s", err)
	}
	return &getTokenResult.Credentials, nil
}

// GetAWSConsoleURL builds a URL that can be used to access the AWS console
// with the provided console. If uri is specified, it is appended to the AWS
// console URL (https://console.aws.amazon.com/)
func GetAWSConsoleURL(credentials *sts.Credentials, uri string) (string, error) {
	session := map[string]string{
		"sessionId":    credentials.AccessKeyId,
		"sessionKey":   credentials.SecretAccessKey,
		"sessionToken": credentials.SessionToken,
	}
	sessionString, err := json.Marshal(session)
	if err != nil {
		panic(err)
	}

	federationValues := url.Values{}
	federationValues.Add("Action", "getSigninToken")
	federationValues.Add("Session", string(sessionString))
	federationURL := "https://signin.aws.amazon.com/federation?" +
		federationValues.Encode()

	federationResponse, err := http.Get(federationURL)
	if err != nil {
		return "", fmt.Errorf("fetching federated signin URL: %s", err)
	}
	tokenDocument := struct{ SigninToken string }{}
	err = json.NewDecoder(federationResponse.Body).Decode(&tokenDocument)
	if err != nil {
		return "", err
	}

	values := url.Values{}
	values.Add("Action", "login")
	values.Add("Destination",
		"https://console.aws.amazon.com/"+strings.TrimPrefix(uri, "/"))
	values.Add("SigninToken", tokenDocument.SigninToken)

	return "https://signin.aws.amazon.com/federation?" + values.Encode(), nil
}
