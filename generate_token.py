#!/usr/bin/python3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jws

example_payload = {
    'auth_time': 1661682509,
    'iss': '<tenant_url>/<application_id>/',
    'iat': 1661683317,
    'aud': '<client_id>',
    'unique_name': 'demo_user_name',
    'exp': 1661701317,
    'sub': '<user_uuid>',
    'nonce': 'abc',
    'user_roles': ['System Administrator', 'Everybody'],
    'last_login': '1682230968',
    'aws_region': 'us-east-1',
}

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private_key_in_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
                                               encryption_algorithm=serialization.NoEncryption())
signed_token = jws.sign(example_payload, private_key_in_pem, algorithm='RS256')
print(signed_token)
