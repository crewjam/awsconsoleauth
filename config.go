package awsconsoleauth

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/crowdmob/goamz/aws"
	"github.com/crowdmob/goamz/s3"
	"github.com/drone/config"
)

var configURLString = flag.String("config", "", "The path to the configuration file")

// LoadConfig loads the configuration from the URL specified by the -config
// flag. URLs may be either file://<local path> or s3://bucket/path in S3.
func LoadConfig() error {
	config.SetPrefix("AWSAUTHD_")

	configURL, err := url.Parse(*configURLString)
	if err != nil {
		return err
	}
	if configURL.Scheme == "file" {
		fmt.Printf("%s\n", configURL.Path)
		return config.Parse("/" + configURL.Path)
	}
	if configURL.Scheme == "s3" {
		return LoadConfigFromS3(configURL.Host, configURL.Path)
	}
	return fmt.Errorf("unknown config URL scheme: %s", configURL.Scheme)
}

// LoadConfigFromS3 loads a configuration from the given S3 bucket and path.
func LoadConfigFromS3(bucketName, path string) error {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = aws.InstanceRegion()
	}
	if region == "unknown" {
		region = "us-east-1"
	}

	auth, err := aws.GetAuth("", "", "", time.Time{})
	if err != nil {
		return fmt.Errorf("connecting to AWS: %s", err)
	}

	bucket := s3.New(auth, aws.GetRegion(region)).Bucket(bucketName)
	configContents, err := bucket.Get(path)
	if err != nil {
		return fmt.Errorf("fetching s3://%s%s: %s", bucketName, path, err)
	}

	return config.ParseBytes(configContents)
}
