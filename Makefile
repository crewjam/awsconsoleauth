
.PHONY: help build create update put-config

include cloudformation.mk

help:
	@echo "Available targets:"
	@echo ""
	@echo " build      - build the Docker image and push it to the docker hub"
	@echo " create     - create a cloudformation stack"
	@echo " update     - update the cloudformation stack"

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
	    ParameterKey=GoogleDomain,ParameterValue=$(GOOGLE_DOMAIN) \
	    ParameterKey=GoogleClientID,ParameterValue=$(GOOGLE_CLIENT_ID) \
	    ParameterKey=GoogleClientSecret,ParameterValue=$(GOOGLE_CLIENT_SECRET) \
	    ParameterKey=GoogleServiceEmail,ParameterValue=$(GOOGLE_SERVICE_EMAIL) \
	    ParameterKey=GoogleServicePrivateKey,ParameterValue="$(GOOGLE_SERVICE_PRIVATE_KEY)" \
	    ParameterKey=GoogleServiceUser,ParameterValue=$(GOOGLE_SERVICE_USER) \
	    ParameterKey=DockerImage,ParameterValue=$(DOCKER_IMAGE):latest

update:
	aws cloudformation update-stack --stack-name $(STACK_NAME) \
	  --template-body='$(shell cat cloudformation.template)' \
	  --capabilities=CAPABILITY_IAM \
	  --parameters \
	    ParameterKey=DnsName,ParameterValue=$(DNS_NAME) \
	    ParameterKey=KeyPair,ParameterValue=$(KEY_PAIR) \
	    ParameterKey=FrontendSSLCertificateARN,ParameterValue=$(CERTIFICATE_ARN) \
	    ParameterKey=GoogleDomain,ParameterValue=$(GOOGLE_DOMAIN) \
	    ParameterKey=GoogleClientID,ParameterValue=$(GOOGLE_CLIENT_ID) \
	    ParameterKey=GoogleClientSecret,ParameterValue=$(GOOGLE_CLIENT_SECRET) \
	    ParameterKey=GoogleServiceEmail,ParameterValue=$(GOOGLE_SERVICE_EMAIL) \
	    ParameterKey=GoogleServicePrivateKey,ParameterValue=$(GOOGLE_SERVICE_PRIVATE_KEY) \
	    ParameterKey=GoogleServiceUser,ParameterValue=$(GOOGLE_SERVICE_USER) \
	    ParameterKey=DockerImage,UsePreviousValue=true
