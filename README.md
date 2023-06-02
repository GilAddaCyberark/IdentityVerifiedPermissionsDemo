# Identity Verified Permissions Demo

**Disclaimer:**  This is not production grade code. Do not use it as-is for production systems.

A Lambda authorizer is an API Gateway feature that uses a Lambda function to control access to your API.
This is a demo project to present API Gateway access control based on Amazon Verified Permissions as the access control engine and
am API Gateway Lambda authorizer as the method to control the access to API Gateway resources.

The access control will use CyberArk Identity Oauth2.0 Token / ID Token and run the authorization using the Amazon Verified Permissions service.
To create a token-based Lambda authorizer function, we shall create a Python Lambda deployment package and upload it as a zip.

![Amazon Verified Permissions](architecture.png "Flow and Architecture of the lambda authorizer" )

## Prepare an Amazon API Gateway with a token authorizer and a sample protected resource
To create the API Gateway with the token authorizer code and a resource
``` bash
    ./prepare_authorizer_package.sh <s3 bucket name> <verified permissions policy store id> <cyberark identity url>
```

For example 
``` bash
    ./prepare_authorizer_package.sh avp-demo-bucket  ps-1234-5678 https://xxxx.id.integration-cyberark.cloud/
```

### Lambda Authorizer token authorizer performs:
* Validate token signature and extracts the claims in it
* Retrieve user attributes
* Formalize the token claims to Amazon Verified Permissions format
* Invokes an authorization check using Amazon Verified Permissions and gets the decision
* Converts the decision to an IAM Policy format and returns it (to the API Gateway)

## Testing the setup
Install the prerequisites
```bash
pip install requests==2.29.0 requests-oauth2client python-jose
```
To invoke the script run:  
```bash
python access-demo-resource.py -u <username> -p <password> -i <identity url> -g  <resource url>
```

### Comments 
1. the user name should be in this pattern: user_name@cyberark_identity_domain. 
e.g. my_user@trialdomain
2. You can change the user attributes. e.g. user_dept = 'dev' and see you are unauthorized to do so.

In case you are authorized, the result message is “Hello from Lambda!” 
otherwise, you will get “User is not authorized to access this resource with an explicit deny”. 

### Troubleshooting
These are the common steps to troubleshoot:
1. If you get "Could not resolve host, it may be a wrong API Gateway address.
2. Review AWS CloudWatch Logs of the Lambda authorizer function. Verify a call on the time you performed the request.
3. Check that the logs contain the inputs to the Lambda authorizer as the authorization header and method ARN.
4. Check the result of the Lambda authorizer that you get an Allow decision from Amazon Verified Permissions
5. Check that the authorization token is in the correct format. You can use jwt.io to decode it online.

