#!/bin/bash
rm -rf package
mkdir -p package

cp ./lambda_function.py package
pip install python-jose requests --target package

zip package