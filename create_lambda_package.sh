#!/bin/bash
# clean the lambda function package directory
# Maybe don't run destructive commands in this script? maybe better they fail if its there?
# rm -rf package
mkdir -p package

# copy function code and install packages
cp ./lambda_function.py package
pip install python-jose requests --target package

# temporary copy last boto3 version that supports Amazon Verified Permissions
# You have a reference to your user folder...?
cp -r /Users/Gil.Adda/dev/policy-decision-service/boto3 package
# You have a reference to your user folder...?
cp -r /Users/Gil.Adda/dev/policy-decision-service/botocore package

# package the authorizer and packages to a zip file
rm lambda_authorizer_package.zip
pushd package
zip -r ../lambda_authorizer_package.zip .
popd

# upload the package to the lambda function
aws lambda update-function-code --function-name  avp_authorizer \
  --zip-file fileb://lambda_authorizer_package.zip

# What about windows users?
