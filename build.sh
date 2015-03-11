#!/bin/sh
set -e
docker build -t crewjam/awsauthproxy .
docker tag -f crewjam/awsauthproxy crewjam/awsauthproxy:latest
docker push crewjam/awsauthproxy:latest
