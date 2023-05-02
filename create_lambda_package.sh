#!/bin/bash
# clean the lambda function package directory
rm -rf package
mkdir -p package

# copy function code and install pacja
cp ./lambda_function.py package
pip install python-jose requests --target package

# temporary copy last boto3 version that supports Amazon Verified Permissions
cp -r /Users/Gil.Adda/dev/policy-decision-service/boto3 package
cp -r /Users/Gil.Adda/dev/policy-decision-service/botocore package

# package the authorizer and packages to a zip file
rm lambda_authorizer_package.zip
pushd package
zip -r ../lambda_authorizer_package.zip .
popd

# upload the package to the lambda function
aws lambda update-function-code --function-name  avp_authorizer \
  --zip-file fileb://lambda_authorizer_package.zip
