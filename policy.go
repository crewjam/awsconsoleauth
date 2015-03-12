package awsconsoleauth

import (
	"bytes"
	"encoding/json"
)

// PolicyRecord represents a single policy record. Each record has a `Name` that
// identifies it and a `Policy` which is the text of the policy record.
type PolicyRecord struct {
	Name   string
	Policy string
}

// PolicyRecords is the ordered list of policy records
var PolicyRecords = []PolicyRecord{
	{
		Name: "aws-admin",
		Policy: mustMinifyJSON(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Sid": "Stmt1",
				"Effect": "Allow",
				"Action":"*",
				"Resource":"*"
			}]
		}`),
	},
	{
		Name: "aws-users",
		Policy: mustMinifyJSON(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "NotAction": "iam:*",
      "Resource": "*"
    }
  ]
}`),
	},
	{
		Name: "aws-read-only",
		Policy: mustMinifyJSON(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "autoscaling:Describe*",
        "cloudformation:Describe*",
        "cloudformation:Get*",
        "cloudformation:List*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "dynamodb:Get*",
        "dynamodb:BatchGet*",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "ec2:Describe*",
        "elasticache:Describe*",
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
        "route53:Get*",
        "route53:List*",
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
        "tag:get*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}`),
	},
}

func mustMinifyJSON(input string) string {
	output := bytes.NewBuffer(nil)
	if err := json.Compact(output, []byte(input)); err != nil {
		panic(err)
	}
	return output.String()
}

// MapUserAndGroupsToPolicy returns the policy for the specified user and
// groups.
//
// This PolicyRecords list is examined in order. For each record here we check
// if the user is a memeber of the corresponding group. If she is, then the
// associated policy is applied.
//
// If no policy matches, this function returns (nil, nil).
func MapUserAndGroupsToPolicy(user string, groups []string) (*PolicyRecord, error) {
	groupNames := map[string]struct{}{}
	for _, groupName := range groups {
		groupNames[groupName] = struct{}{}
	}

	for _, policyRecord := range PolicyRecords {
		_, ok := groupNames[policyRecord.Name]
		if !ok {
			continue
		}

		return &policyRecord, nil
	}
	return nil, nil
}
