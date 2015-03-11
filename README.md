
# How It Works

- Your users navigate to this service.
- We redirect them through the goole login process.
- We check their group membership to determine which access policy to apply
- We generate credentials using the AWS token service and the GetFederationToken
  API.
- We build a URL to the AWS console that contains their temporary credentials 
  and redirect the there.

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
   provided CloudFormation template. Alternately you can use the provided 
   creation script.
   
        cp create.sh.template create.sh
        vi create.sh  # fill in the parameters
        ./create.sh
