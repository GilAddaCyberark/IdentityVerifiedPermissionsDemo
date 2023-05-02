# IdentityVerifiedPermissionsDemo
A Lambda authorizer is an API Gateway feature that uses a Lambda function to control access to your API.
This is a demo project to present API Gateway access control based on Amazon Verified Permissions as the access control engine and
am API Gateway Lambda authorizer as the method to control the access to API Gateway resources.

The access control will use, CyberArk Identity Oauth2.0 Token / ID Token and run the authorization using Amazon Verified Permissions service.
To create a token-based Lambda authorizer function, we shall create a Python lambda deployment package and upload it as a zip.


![Amazon Verified Permissions](architecture.png "Flow and Architecture of the lambda authorizer" )


## Upload the code to the Lambda Authorizer
to prepare and upload the Lambda authorizer package run the follwign code
``` bash
    ./create_lambda_package.sh
```

## The Lambda authorizer
The Lambda Authorizer receives the OIDC token as a bearer token and the API Gateway method we want to protect
The following environment variables should be set on the Lambda function confiuration:
TENANT_IDENTITY_URL - the root url of CyberArk Identity account you received
POLICY_STORE_ID - the id of the Amazon Verified Permissions policy store

The logic that the lambda performs is:
* Validate token signatire and extracts the claims in it
* Formalize the token claims to Amazon Verified Permissions format
* Invokes an authorization check using Amazon Verified Permissions and gets the decision
* Converts the decision to an IAM Policy format and returns it (to the API Gateway)
