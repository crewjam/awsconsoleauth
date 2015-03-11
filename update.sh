#!/bin/bash
stack_name=${1-authproxy}
aws cloudformation update-stack --stack-name $stack_name \
  --template-body="$(cat cloudformation.template)" \
  --capabilities=CAPABILITY_IAM \
  --parameters \
    ParameterKey=DnsName,UsePreviousValue=true \
    ParameterKey=KeyPair,UsePreviousValue=true \
    ParameterKey=GoogleClientId,UsePreviousValue=true \
    ParameterKey=GoogleClientSecret,UsePreviousValue=true \
    ParameterKey=GoogleDomain,UsePreviousValue=true \
    ParameterKey=FrontendSSLCertificateARN,UsePreviousValue=true \
    ParameterKey=DockerImage,UsePreviousValue=true