package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crowdmob/goamz/aws"
	"github.com/crowdmob/goamz/iam"
	"github.com/crowdmob/goamz/sts"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var OauthConfig = &oauth2.Config{
	Scopes:   []string{"email", "https://www.googleapis.com/auth/admin.directory.group.readonly"},
	Endpoint: google.Endpoint,
}

var ClientID = flag.String("google-client-id", "", "OAuth Client ID")
var ClientSecret = flag.String("google-client-secret", "", "OAuth Client Secret")

// We reuse the Google client secret as the web secret.
var Secret = ClientSecret

var GoogleLoginTimeout = flag.Duration("google-login-timeout", time.Second*120,
	"The maximum time that we are willing to wait for a login to succeed")

var GoogleDomain = flag.String("google-domain", "", "Restrict the user domain to the specified one.")

var jwtKeys = map[string]interface{}{}

// getOriginUrl returns the HTTP origin string (i.e.
// https://alice.example.com, or http://localhost:8000)
func getOriginURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

func getRemoteAddress(r *http.Request) string {
	remoteAddr := r.RemoteAddr
	if r.Header.Get("X-Forwarded-For") != "" {
		forwardedFor := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		remoteAddr = strings.TrimSpace(forwardedFor[len(forwardedFor)-1])
	}
	return remoteAddr
}

func GetRoot(w http.ResponseWriter, r *http.Request) {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["ua"] = r.Header.Get("User-Agent")
	token.Claims["ra"] = getRemoteAddress(r)
	token.Claims["exp"] = time.Now().Add(*GoogleLoginTimeout).Unix()
	token.Claims["action"] = r.URL.Query().Get("action")
	state, err := token.SignedString([]byte(*Secret))
	if err != nil {
		log.Printf("ERROR: cannot generate token: %s", err)
		http.Error(w, "Authentication failed", 500)
		return
	}

	oauthConfig := *OauthConfig
	oauthConfig.RedirectURL = fmt.Sprintf("%s/callback", getOriginURL(r))

	url := oauthConfig.AuthCodeURL(state)

	http.Redirect(w, r, url, http.StatusFound)
}

// valididateState checks that the state parameter is valid and returns nil if
// so, otherwise it returns a non-nill error value. (Do not show the returned
// error to the user, it might contain security-sensitive information)
func valididateState(r *http.Request, state string) (string, error) {
	token, err := jwt.Parse(state, func(t *jwt.Token) (interface{}, error) {
		return []byte(*Secret), nil
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

	return token.Claims["action"].(string), nil
}

type GroupsResponse struct {
	Groups []Group `json:"groups"`
}

type Group struct {
	Name string `json:"name"`
}

func GetCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	action, err := valididateState(r, state)
	if err != nil {
		log.Printf("ERROR: state: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	oauthConfig := *OauthConfig
	oauthConfig.RedirectURL = fmt.Sprintf("%s/callback", getOriginURL(r))

	oauthToken, err := oauthConfig.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		log.Printf("ERROR: oauth: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token, err := jwt.Parse(oauthToken.Extra("id_token").(string),
		func(t *jwt.Token) (interface{}, error) {
			keyString, ok := jwtKeys[t.Header["kid"].(string)]
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
		log.Printf("ERROR: oauth: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if *GoogleDomain != "" {
		if token.Claims["hd"].(string) != *GoogleDomain {
			log.Printf("ERROR: expected domain %s, got domain %s", *GoogleDomain,
				token.Claims["hd"].(string))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	emailAddress := token.Claims["email"].(string)
	fmt.Printf("login %s from %s\n", emailAddress, getRemoteAddress(r))

	httpClient := oauthConfig.Client(oauth2.NoContext, oauthToken)
	r2, err := httpClient.Get(fmt.Sprintf("https://www.googleapis.com/admin/directory/v1/groups?userKey=%s",
		emailAddress))
	if err != nil {
		log.Printf("ERROR: oauth: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	groupsResponse := GroupsResponse{}
	if err := json.NewDecoder(r2.Body).Decode(&groupsResponse); err != nil {
		log.Printf("ERROR: oauth: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	groupNames := map[string]struct{}{}
	for _, group := range groupsResponse.Groups {
		groupNames[group.Name] = struct{}{}
	}

	policyString := ""
	for _, policyRecord := range PolicyRecords {
		_, ok := groupNames[policyRecord.Name]
		if ok {
			log.Printf("%s: assigned policy %s", emailAddress, policyRecord.Name)
			policyString = policyRecord.Policy
			break
		}
	}
	if policyString == "" {
		log.Printf("%s: access denied", emailAddress)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if action == "key" {
		getTokenResult, err := stsConnection.GetFederationToken(emailAddress,
			policyString, 43200)
		if err != nil {
			log.Printf("ERROR: oauth: %s", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-type", "text-plain")
		fmt.Fprintf(w, "# expires %s\n", getTokenResult.Credentials.Expiration)
		fmt.Fprintf(w, "AWS_ACCESS_KEY_ID=%s\n", getTokenResult.Credentials.AccessKeyId)
		fmt.Fprintf(w, "AWS_SECRET_ACCESS_KEY=%s\n", getTokenResult.Credentials.SecretAccessKey)
		fmt.Fprintf(w, "AWS_TOKEN=%s\n", getTokenResult.Credentials.SessionToken)
		return
	}

	redirectURL, err := GetAWSConsoleURLForUser(emailAddress, policyString)
	if err != nil {
		log.Printf("ERROR: %s", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

type PolicyRecord struct {
	Name   string
	Policy string
}

var PolicyRecords = []PolicyRecord{
	{
		Name: "aws-admin",
		Policy: `{
			"Version": "2012-10-17",
			"Statement": [{
				"Sid": "Stmt1",
				"Effect": "Allow",
				"Action":"*",
				"Resource":"*"
			}]
		}`,
	},
	{
		Name: "aws-read-only",
		Policy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "appstream:Get*",
        "autoscaling:Describe*",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResource",
        "cloudformation:DescribeStackResources",
        "cloudformation:GetTemplate",
        "cloudformation:List*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "directconnect:Describe*",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "ec2:Describe*",
        "elasticache:Describe*",
        "elasticbeanstalk:Check*",
        "elasticbeanstalk:Describe*",
        "elasticbeanstalk:List*",
        "elasticbeanstalk:RequestEnvironmentInfo",
        "elasticbeanstalk:RetrieveEnvironmentInfo",
        "elasticloadbalancing:Describe*",
        "elasticmapreduce:Describe*",
        "elasticmapreduce:List*",
        "elastictranscoder:Read*",
        "elastictranscoder:List*",
        "iam:List*",
        "iam:Get*",
        "kinesis:Describe*",
        "kinesis:Get*",
        "kinesis:List*",
        "opsworks:Describe*",
        "opsworks:Get*",
        "route53:Get*",
        "route53:List*",
        "redshift:Describe*",
        "redshift:ViewQueriesInConsole",
        "rds:Describe*",
        "rds:ListTagsForResource",
        "s3:Get*",
        "s3:List*",
        "sdb:GetAttributes",
        "sdb:List*",
        "sdb:Select*",
        "ses:Get*",
        "ses:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sqs:ReceiveMessage",
        "storagegateway:List*",
        "storagegateway:Describe*",
        "tag:get*",
        "trustedadvisor:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}`,
	},
	{
		Name: "aws-users",
		Policy: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "NotAction": "iam:*",
      "Resource": "*"
    }
  ]
}`,
	},
}

func GetAWSConsoleURLForUser(emailAddress string, policString string) (string, error) {
	getTokenResult, err := stsConnection.GetFederationToken(emailAddress, policString, 900)
	if err != nil {
		return "", err
	}

	session := map[string]string{
		"sessionId":    getTokenResult.Credentials.AccessKeyId,
		"sessionKey":   getTokenResult.Credentials.SecretAccessKey,
		"sessionToken": getTokenResult.Credentials.SessionToken,
	}
	sessionString, err := json.Marshal(session)
	if err != nil {
		return "", err
	}

	federationValues := url.Values{}
	federationValues.Add("Action", "getSigninToken")
	federationValues.Add("Session", string(sessionString))
	federationURL := "https://signin.aws.amazon.com/federation?" + federationValues.Encode()

	federationResponse, err := http.Get(federationURL)
	if err != nil {
		return "", err
	}
	tokenDocument := struct{ SigninToken string }{}
	err = json.NewDecoder(federationResponse.Body).Decode(&tokenDocument)
	if err != nil {
		return "", err
	}

	values := url.Values{}
	values.Add("Action", "login")
	if *GoogleDomain != "" {
		values.Add("Issuer", *GoogleDomain)
	}
	values.Add("Destination", "https://console.aws.amazon.com/")
	values.Add("SigninToken", tokenDocument.SigninToken)

	return "https://signin.aws.amazon.com/federation?" + values.Encode(), nil
}

var stsConnection *sts.STS
var iamConnection *iam.IAM

type TimeValue struct {
	Value time.Time
}

func (t *TimeValue) String() string {
	return t.Value.String()
}

func (t *TimeValue) Set(v string) error {
	var err error
	t.Value, err = time.Parse(time.RFC3339, v)
	return err
}

func main() {
	listenAddress := flag.String("listen", ":8080", "The address the web server should listen on")

	region := flag.String("aws-region", "", "AWS region (i.e. us-east-1)")
	accessKey := flag.String("aws-access-key", "", "AWS access key")
	secretKey := flag.String("aws-secret-key", "", "AWS secret key")
	token := flag.String("aws-token", "", "AWS token")
	expiration := TimeValue{}
	flag.Var(&expiration, "aws-expiration", "AWS expiration")

	flag.Parse()

	// Configure OAuth
	OauthConfig.ClientID = *ClientID
	OauthConfig.ClientSecret = *ClientSecret
	if *GoogleDomain != "" {
		OauthConfig.Endpoint.AuthURL += fmt.Sprintf("?hd=%s", *GoogleDomain)
	}

	// Fetch the google keys for oauth
	googleCertsResponse, err := http.Get("https://www.googleapis.com/oauth2/v1/certs")
	if err != nil {
		panic(err)
	}
	if err := json.NewDecoder(googleCertsResponse.Body).Decode(&jwtKeys); err != nil {
		panic(err)
	}

	// Configure AWS STS
	if *region == "" {
		*region = aws.InstanceRegion()
		if *region == "unknown" {
			*region = "us-east-1"
		}
	}

	auth, err := aws.GetAuth(*accessKey, *secretKey, *token, expiration.Value)
	if err != nil {
		panic(err)
	}

	//WhatGroupsIsRossIn()

	stsConnection = sts.New(auth, aws.GetRegion(*region))
	iamConnection = iam.New(auth, aws.GetRegion(*region))

	http.HandleFunc("/", GetRoot)
	http.HandleFunc("/callback", GetCallback)

	fmt.Printf("Listening on %s\n", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
