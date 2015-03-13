
.PHONY: help build create update put-config

include cloudformation.mk

help:
	@echo "Available targets:"
	@echo ""
	@echo " build      - build the Docker image and push it to the docker hub"
	@echo " create     - create a cloudformation stack"
	@echo " update     - update the cloudformation stack"
	@echo " put-config - copy awsauthd.conf to S3"

build:
	docker build -t $(DOCKER_IMAGE) .
	docker tag -f $(DOCKER_IMAGE) $(DOCKER_IMAGE):latest
	docker push $(DOCKER_IMAGE):latest

create:
	aws cloudformation create-stack --stack-name $(STACK_NAME) \
	  --template-body="$(cat cloudformation.template)" \
	  --capabilities=CAPABILITY_IAM \
	  --parameters \
	    ParameterKey=DnsName,ParameterValue=$(DNS_NAME) \
	    ParameterKey=KeyPair,ParameterValue=$(KEY_PAIR) \
	    ParameterKey=FrontendSSLCertificateARN,ParameterValue=$(CERTIFICATE_ARN) \
	    ParameterKey=DockerImage,ParameterValue=$(DOCKER_IMAGE):latest

update:
	aws cloudformation update-stack --stack-name $(STACK_NAME) \
	  --template-body='$(shell cat cloudformation.template)' \
	  --capabilities=CAPABILITY_IAM \
	  --parameters \
	    ParameterKey=DnsName,UsePreviousValue=true \
	    ParameterKey=KeyPair,UsePreviousValue=true \
	    ParameterKey=FrontendSSLCertificateARN,UsePreviousValue=true \
	    ParameterKey=DockerImage,UsePreviousValue=true

put-config:
	aws s3 cp awsauthd.conf s3://$(shell aws cloudformation \
	  describe-stack-resources --stack-name $(STACK_NAME) \
	  --logical-resource-id DataBucket --output text | cut -f3)/awsauthd.conf
