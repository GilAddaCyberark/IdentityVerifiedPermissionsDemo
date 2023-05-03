#!/bin/bash
set -e
# prepare package to deploy: copy function code and install packages
mkdir -p package
cp ./lambda_function.py package
pip install python-jose requests --target package
# temporary copy last boto3 version that supports Amazon Verified Permissions
# this will be deleted when boto3 will support Amazon Verified Permissions
cp -r boto3 package
cp -r botocore package