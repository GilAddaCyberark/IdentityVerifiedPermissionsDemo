#!/bin/bash
set -e
# prepare package to deploy: copy function code and install packages
mkdir -p package
cp ./lambda_function.py package
pip install python-jose requests==2.29.0 --target package
# temporary copy last boto3 version that supports Amazon Verified Permissions
# this will be deleted when boto3 will support Amazon Verified Permissions
unzip -o boto.zip -d package

export BUCKET_NAME=$1
aws cloudformation package --template avp-authorizer-cf-template.yaml \
 --s3-bucket $BUCKET_NAME --output-template-file cf-package.yaml

export POLICY_STORE_ID=$2
export IDENTITY_URL=$3

aws cloudformation deploy --template-file cf-package.yaml \
--stack-name avp-authorizer-stack --capabilities CAPABILITY_NAMED_IAM \
--parameter-overrides policyStoreID=$POLICY_STORE_ID IdentityTenantUrl=$IDENTITY_URL