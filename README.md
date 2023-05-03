# Identity Verified Permissions Demo

**Disclaimer:**  This is not production grade code. Do not use it as-is for production systems.

A Lambda authorizer is an API Gateway feature that uses a Lambda function to control access to your API.
This is a demo project to present API Gateway access control based on Amazon Verified Permissions as the access control engine and
am API Gateway Lambda authorizer as the method to control the access to API Gateway resources.

The access control will use CyberArk Identity Oauth2.0 Token / ID Token and run the authorization using the Amazon Verified Permissions service.
To create a token-based Lambda authorizer function, we shall create a Python Lambda deployment package and upload it as a zip.


![Amazon Verified Permissions](architecture.png "Flow and Architecture of the lambda authorizer" )


## Prepaee the Lambda Authorizer code and dependency in temp dir
to prepare and upload the Lambda authorizer package run the follwing code
``` bash
    ./prepare_authorizer_package.sh
```
## Create the API Gateway with an AVP Autorizer and custom lambda
Set your bucket name in the command below to prepare the package for deploy
```commandline
aws cloudformation package --template avp-authorizer-cf-template.yaml \
 --s3-bucket <your bucket name> --output-template-file cf_package.yaml
```
Deploy the Cloud Formation template
Set your Amazon Verified Permissions policy store id, identity-tenant-url
```commandline
aws cloudformation deploy --template-file cf_package.yaml \
--stack-name avp-authorizer-stack --capabilities CAPABILITY_NAMED_IAM \
--parameter-overrides policyStoreID='<your policy store id>' IdentityTenantUrl='<your identity url>'
```

## The lambda authorizer
The lambda authorizer receives the OIDC token as a bearer token and the API Gateway method we want to protect.
The following environment variables should be set on the Lambda function confiuration:
TENANT_IDENTITY_URL - the root url of CyberArk Identity account you received
POLICY_STORE_ID - the id of the Amazon Verified Permissions policy store

The logic of the lambda performs:
* Validate token signature and extracts the claims in it
* Formalize the token claims to Amazon Verified Permissions format
* Invokes an authorization check using Amazon Verified Permissions and gets the decision
* Converts the decision to an IAM Policy format and returns it (to the API Gateway)


## Testing the setup
use a web client such as curl with the API Gateway url and the id token receved from identity
run the command example below
```commandline
curl https://<api-id>.execute-api.<regiion>.amazonaws.com/test/protected-resource -X POST -H "Authorization: Bearer <oidc token>.."
```

you can generate a self-signed token to test the integration using this command
pre-requisites cryptography and python-jose are installed
```commandline
python generate_token.py
```
