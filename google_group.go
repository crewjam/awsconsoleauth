package awsconsoleauth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/drone/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

// GroupsResponse respresents the response we get from the Google Directory API
// to a request for the group membership of a user.
type GroupsResponse struct {
	Groups []Group `json:"groups"`
}

// Group respresents a single group that a user is a member of
type Group struct {
	Name string `json:"name"`
}

const rsaKeyPrefix = "-----BEGIN RSA PRIVATE KEY-----"

func formatRsaKey(key string) string {
	// If this came from the config file it should be formatted right
	if !strings.HasPrefix(key, rsaKeyPrefix) {
		// Replace spaces in the key with newlines. This makes it
		// easier to pass the key in an environment variable
		key = strings.Replace(key, " ", "\n", -1)
		key = fmt.Sprintf("%s\n%s\n-----END RSA PRIVATE KEY-----", rsaKeyPrefix, key)
	}

	return key
}

var (
	googleServiceEmail      = config.String("google-service-email", "")
	googleServicePrivateKey = config.String("google-service-private-key", "")
	googleServiceUser       = config.String("google-service-user", "")
)

// InitializeGoogleGroup checks that our Google service account is able to fetch
// group membership for a user (It users the `google-service-user` to test).
func InitializeGoogleGroup() error {
	*googleServicePrivateKey = formatRsaKey(*googleServicePrivateKey)

	groups, err := GetUserGroups(*googleServiceUser)
	if err != nil {
		return fmt.Errorf("Google groups doesn't work: %s", err)
	}
	fmt.Printf("google groups test: passed (user %s is a member of %#v)\n",
		*googleServiceUser, groups)
	return nil
}

// GetUserGroups returns the names of the groups that the specified user is a
// member of.
func GetUserGroups(emailAddress string) ([]string, error) {
	conf := jwt.Config{
		Email:      *googleServiceEmail,
		PrivateKey: []byte(*googleServicePrivateKey),
		Scopes:     []string{"https://www.googleapis.com/auth/admin.directory.group.readonly"},
		TokenURL:   google.JWTTokenURL,
		Subject:    *googleServiceUser,
	}

	client := conf.Client(oauth2.NoContext)
	response, err := client.Get(fmt.Sprintf("https://www.googleapis.com/admin/directory/v1/groups?userKey=%s", emailAddress))
	if err != nil {
		return nil, fmt.Errorf("fetching groups: %s", err)
	}
	if response.StatusCode != 200 {
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("fetching groups: returned %s", response.Status)
		}
		return nil, fmt.Errorf("fetching groups: returned %s: %s",
			response.Status, responseBody)
	}

	groupsResponse := GroupsResponse{}
	if err := json.NewDecoder(response.Body).Decode(&groupsResponse); err != nil {
		return nil, fmt.Errorf("parsing groups response: %s", err)
	}

	groupNames := []string{}
	for _, group := range groupsResponse.Groups {
		groupNames = append(groupNames, group.Name)
	}
	return groupNames, nil
}
