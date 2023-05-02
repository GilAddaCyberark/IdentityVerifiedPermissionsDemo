# IdentityVerifiedPermissionsDemo
A Lambda authorizer is an API Gateway feature that uses a Lambda function to control access to your API. 
This is a demo project to present API Gateway access control based on Amazon Verified Permissions as the access control engine and 
am API Gateway Lambda authorizer as the method to control the access to API Gateway resources.

The access control will use, CyberArk Identity Oauth2.0 Token / ID Token and run the authorization using Amazon Verified Permissions service.
To create a token-based Lambda authorizer function, we shall create a Python lambda deployment package and upload it as a zip.

## Upload the code to the Lambda Authorizer
to prepare and upload the Lambda authorizer package run the follwign code
``` bash
    ./create_lambda_package.sh
```
