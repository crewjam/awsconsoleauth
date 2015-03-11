
# Setup

1. Get a Google OAuth Client ID and Secret.
 
   - Navigate to https://console.developers.google.com/
   - Click "Create Project"
   - Navigate to "APIs & Auth" and then "Credentials"
   - Click "Create Client ID"
   - Select "Web Application" and set up the consent screen.
   - Under authorized javascript origins, enter the name of your server, i.e.
     `https://aws.example.com`
   - Under "AUTHORIZED REDIRECT URIS" choose `https://aws.example.com/oauth2callback`
   - Click "Create client ID".
   - record your client ID and client secret.
 
2. Get an SSL certificate for your domain and upload it to the AWS IAM console.
   Note the ARN for your new certificate.
   
        aws iam upload-server-certificate --server-certificate-name aws.example.com \
          --certificate-body file://ssl.crt \
          --private-key file://ssl.key \
          --certificate-chain file://intermediate.crt

3. Navigate to https://console.aws.amazon.com/cloudformation and use the 
   provided CloudFormation template.
   
   
        ParameterKey=DnsName,ParameterValue=$DNS_NAME \
        ParameterKey=KeyPair,ParameterValue=<your aw \
                        
aws iam upload-server-certificate --server-certificate-name aws.example.com \
  --certificate-body file://ssl.crt \
  --private-key file://ssl.key \
  --certificate-chain file://intermediate.crt