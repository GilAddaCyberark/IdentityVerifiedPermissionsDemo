#!/usr/bin/python3
import argparse
import json

import requests

HTTP_VERY_LONG_TIMEOUT = 300
identity_headers = {'Content-Type': 'application/json', 'X-IDAP-NATIVE-CLIENT': 'true'}


def identity_login(identity_url: str, username:str, password: str) ->str:
    try:

        # 1st Phase - get user challenge (maybe password, password etc)
        response = requests.api.post(f'{identity_url}/Security/StartAuthentication', json={
            'User': username,
            'Version': '1.0',
            'PlatformTokenResponse': True
        }, headers= identity_headers, timeout=HTTP_VERY_LONG_TIMEOUT)
        auth_response = json.loads(response.text)
        mechanism_id = auth_response['Result']['Challenges'][0]['Mechanisms'][0]['MechanismId']
        session_id = auth_response['Result']['SessionId']

        # 2nd Phase - respond with password
        response = requests.api.post(
            f'{identity_url}/Security/AdvanceAuthentication', json={
                'SessionId': session_id,
                'MechanismId': mechanism_id,
                'Action': 'Answer',
                'Answer': password
            }, headers=identity_headers, timeout=HTTP_VERY_LONG_TIMEOUT)
        advanced_auth_result = json.loads(response.text)
        token = advanced_auth_result['Result']['Token']
        return token
    except (Exception) as ex:
        print(ex)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user')
    parser.add_argument('-p', '--password')
    parser.add_argument('-i', '--identity_url')
    parser.add_argument('-g', '--gw_url')
    args = parser.parse_args()

    # login and get token
    token = identity_login(username=args.user, password=args.password, identity_url=args.identity_url)

    # call api gateway resource, protected by token authorizer and Amazon Verified Permissions as the decision service
    print(f'token: {token}')
    url =  f'{args.gw_url}/protected-resource'
    headers = { 'Authorization' : f'Bearer {token}' }
    response = requests.api.post(url,data={}, headers=headers)
    print(response)


if __name__ == "__main__":
    main()

