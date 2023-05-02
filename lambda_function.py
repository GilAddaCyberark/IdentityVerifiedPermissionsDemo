import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List

import boto3
import requests
from jose import jwk, jwt
from jose.utils import base64url_decode

logger = logging.getLogger()
logger.setLevel(logging.INFO)

avp_client = boto3.client('verified-permissions')


def lambda_handler(event, context) -> Dict:
    """Authorize user access based on the token information and policies stored at Amazon Verified Permissions
    Parameters:
        event (Dict): A dictionary containing the method arn and authorization token
        (see here: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-input.html)

        context (Lambda Context):  The lambda function context

    Returns:
        IAM policy (Dict): a dictionary representing the IAM policy with the effect (Deny / Allow)

    More info on CyberArk Identity tokens can be found here:
       id tokens - https://identity-developer.cyberark.com/docs/id-tokens
       access token - https://identity-developer.cyberark.com/docs/access-tokens
    """

    # Validate oidc token signature and get the claims in the token.
    token = event['authorizationToken'].replace('Bearer', '').strip()

    verify_oidc_token_signature(token)

    claims = jwt.get_unverified_claims(token)

    # Extract token information
    principalId = claims['sub']
    logger.info(f'principal: {principalId}')

    method_arn = event['methodArn']
    apiGatewayMethod = method_arn.split(':')[5].split('/')

    # Calculating the action as a concatenation of the rest method and resource name
    method = apiGatewayMethod[2]
    resource = apiGatewayMethod[-1]

    # Call Amazon Verified Permissions to authorize. The return value is Allow / Deny and can be assigned to the IAM Policy
    effect = check_authorization(principal_id=claims['sub'], action=method, resource=resource, claims=claims)

    # Build the output
    policy_response = generate_iam_policy(principalId=principalId, effect=effect, resource=method_arn)
    logger.info(f'response: {policy_response}')

    return policy_response


def generate_iam_policy(principalId: str, effect: str, resource: str) -> Dict:
    """
    This method generates the IAM policy to allow / deny access to the Amazon API Gateway resource
    Parameters
        principalId: Principal to validate
        effect (str): Allow or Deny
        resource (str): Name of the API Gateway resource

    :return: Dictionary containing the IAM policy
    """
    policy = {
        'principalId': principalId,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }

    return policy


def _get_identity_tanant_public_key(oidc_token: str) -> jwk.Key:
    tenant_url = os.environ.get('TENANT_IDENTITY_URL')
    if not tenant_url:
        raise ValueError('identity tenant url not set')
    key_url = f'{tenant_url}/OAuth2/Keys/__idaptive_cybr_user_oidc/'
    response = requests.get(url=key_url, headers={'Authorization': f'Bearer {oidc_token}'},
                            timeout=60)  # it is advised to cache the key results
    response_dict = json.loads(response.text)
    key = response_dict['keys'][0]

    return jwk.construct(key)


def verify_oidc_token_signature(oidc_token: str) -> bool:
    """
    this function gets the token signature public key from CyberArk Identity.
    and validate the token signature. TBD - Validate time

    Parameters:
        oidc_token (str): an OIDC token string which contains the user authentication

    Returns:
        result (bool): True of valid

    Raises:
        Value Error Exception:

    """

    public_key = _get_identity_tanant_public_key(oidc_token=oidc_token)
    message, encoded_sig = oidc_token.rsplit('.', maxsplit=1)
    decoded_signature = base64url_decode(encoded_sig.encode('utf-8'))
    if not public_key.verify(message.encode('utf8'), decoded_signature):
        raise ValueError('Signature validation with public key failed')

    return True


@dataclass
class Identifier:
    EntityId: str
    EntityType: str


def _get_data_entities(token_claims: Dict) -> List:
    data_entities: List[Dict] = []
    # add roles from token
    for role in token_claims['user_roles']:
        data_entities.append({'Identifier': asdict(Identifier(EntityType='UserGroup', EntityId=role))})

    # add user and role parents
    user_entity = {'Identifier': asdict(Identifier(EntityType='User', EntityId=token_claims['sub'])), 'Parents': []}
    for role in token_claims['user_roles']:
        user_entity['Parents'].append(asdict(Identifier(EntityType='UserGroup', EntityId=role)))
    data_entities.append(user_entity)
    return data_entities


def check_authorization(principal_id: str, action: str, resource: str, claims: Dict) -> str:
    store_id = os.environ.get('POLICY_STORE_ID')
    # REMOVE THIS - you always assume success (that items are there), so why not here also? either check or don't check in all.

    principal = Identifier(EntityType='User', EntityId=principal_id)
    resource = Identifier(EntityType='Resource', EntityId=resource)
    action = {'ActionType': 'Action', 'ActionId': action}
    entities = _get_data_entities(claims)

    # add the resource
    slice_complement = {'Entities': entities}
    context = {
        'aws_region': {
            'String': claims['aws_region']
        },
        'last_login_time': {
            'Long': int(claims['last_login'])
        },
        'login_time': {
            'Long': int(datetime.now(timezone.utc).timestamp())
        },
        'weekday': {
            'Long': datetime.now(timezone.utc).weekday()
        },
    }

    logger.info(f'store id":{store_id}, principal:{asdict(principal)}, action:{action}, resource:{asdict(resource)} context:{context} entities:{slice_complement}')
    authz_response = avp_client.is_authorized(PolicyStoreIdentifier=store_id, Principal=asdict(principal), Resource=asdict(resource),
                                              Action=action, Context=context, SliceComplement=slice_complement)

    return authz_response['Decision']
