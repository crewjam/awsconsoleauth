#!/bin/bash
set -ex
stack_name=${1-authproxy}
aws cloudformation update-stack --stack-name $stack_name \
  --template-body="$(cat cloudformation.template)" \
  --capabilities=CAPABILITY_IAM \
  --parameters \
    ParameterKey=DnsName,UsePreviousValue=true \
    ParameterKey=KeyPair,UsePreviousValue=true \
    ParameterKey=FrontendSSLCertificateARN,UsePreviousValue=true \
    ParameterKey=DockerImage,UsePreviousValue=true

exit 0
while true; do
  bucket=$(aws cloudformation describe-stack-resources --stack-name authproxy --logical-resource-id DataBucket --output text | cut -f3)
  if [ ! -z "$bucket" ]; then
    continue
  fi
done
echo "bucket is $bucket"

aws s3 cp awsauthd.conf s3://$bucket/awsauthd.conf

docker run -d -e AWSAUTHD_AWS_ACCESS_KEY_ID=AKIAI6FCNARSYM4DJFTQ -e AWSAUTHD_AWS_SECRET_ACCESS_KEY=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 -p 80:80 crewjam/awsauthproxy:latest awsauthd -listen=0.0.0.0:80 -config s3://authproxy-databucket-p1pe62giq256/awsauthd.conf