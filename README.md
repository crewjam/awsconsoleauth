
This is a tool to allow authorized folks to log into an AWS account using 
credentials from a Google Apps domain.

# How It Works

- Your users navigate to this service.
- We redirect them through the Google login process.
- We check their group membership in the Google directory service to determine 
  which access policy to apply.
- We generate credentials using the AWS Token service and the GetFederationToken
  API.
- We build a URL to the AWS console that contains their temporary credentials 
  and redirect them there. Alternatively we pass their temporary credentials to
  them directly for use with the AWS API.

Example requests:

- `https://aws.example.com/` eventually redirects to the root of the console.
- `https://aws.example.com/?uri=/ec2/v2/home?region=us-east-1%23Instances:sort=desc:launchTime`
  redirects to the EC2 console view.
- `https://aws.example.com/?view=sh` displays access keys suitable for pasting
  into a bash-style shell:

        # expires 2015-03-14 01:01:04 +0000 UTC
        export AWS_ACCESS_KEY_ID="ASIAJXXXXXXXXXXXXXXX"
        export AWS_SECRET_ACCESS_KEY="uS1aP/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        export AWS_SESSION_TOKEN="AQoD...i6gF"
  
  You can also try `view=csh` and `view=fish`.

# Cloudformation

The cloudformation document creates a load balancer that listens from HTTPS 
connections on TCP/443 and proxies them via HTTP to instances in an autoscaling
group of size 1. At boot, the instances run a the `awsauthproxy` docker image 
which runs `awsauthd`.

`awsauthd` loads its configuration from an S3 bucket that is created by
the cloudformation document. The instance profile allows it to access only this
bucket and nothing else.

The configuration specifies a new set of credentials that are used to execute
the GetFederationToken() API call. These credentials have a policy applied to
them that explicitly disallows reading the configuration bucket. If the 
configuration bucket were not protected, the user could access the 
federation secrets, which would allow them to exceed their authorized access. 

# Setup

1. Get a Google OAuth Client ID and Secret. This is used by the web application
   to authorize your users.
 
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
 
2. Get a Google Service Account. This is used by the application to determine 
   which groups the user is in.
   
   - Navigate to https://console.developers.google.com/
   - Nagivate to your project
   - Click "Create Client ID"
   - Select "Service Account"
   - Note the email address created.
   - Decrypt the certificate that gets downloaded:
         
         openssl pkcs12 -in ~/Downloads/My\ Project-afcee0fea02c.p12 -nodes
   
     Extract the private key part. 

3. Authorize your new google service account. Follow the 
   [directions here](https://developers.google.com/accounts/docs/OAuth2ServiceAccount#delegatingauthority)
   to authorize your new service account to access the scope 
   `https://www.googleapis.com/auth/admin.directory.group.readonly`.

4. Get an SSL certificate for your domain and upload it to the AWS IAM console.
   Note the ARN for your new certificate.
   
        aws iam upload-server-certificate --server-certificate-name aws.example.com \
          --certificate-body file://ssl.crt \
          --private-key file://ssl.key \
          --certificate-chain file://intermediate.crt

5. Build a configuration file from the cloudformation.mk.template filling in all
   your secrets
   
        cp cloudformation.mk.example cloudformation.mk
        vi cloudformation.mk

6. Create the cloudformation stack described by cloudformation.template. You can
   use the provided Makefile, if you you'll need to customize it a little:

        make create
   
   Note: the Makefile assumes you have the AWS CLI installed.
   
7. After a few moments you should be able to upload your config to the S3
   data bucket. 
   
        make put-config
   
# Limitations

- The Google groups and the AWS policy mappings are currently hard coded.

- The size of policy document passed to GetFederationToken() is fairly limited.
  I had to remove stuff from the default ReadOnlyAccess policy to make it fit.

- We don't currently have a way to restrict access to the service launch
  configuration, which exposes the root GetFederationToken() credentials. XXX

- All errors are reported to users in exactly the same way, by returning 
  *400 Bad Request*. This has the benefit of preventing any leakage to 
  unauthorized users but is a little unfriendly. After carefully considering the
  implications, we might want errors that are a little friendlier.
