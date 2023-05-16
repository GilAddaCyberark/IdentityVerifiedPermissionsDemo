#!/usr/bin/python3
import argparse
import requests
from requests_oauth2client import OAuth2Client

HTTP_VERY_LONG_TIMEOUT = 300
identity_headers = {'Content-Type': 'application/json', 'X-IDAP-NATIVE-CLIENT': 'true'}


def identity_login(identity_url: str, username:str, password: str) ->str:
    try:

        oauth2client = OAuth2Client(
            token_endpoint=f"{identity_url}/oauth2/platformtoken",
            auth=(username, password),
        )
        token = oauth2client.client_credentials(scope="", resource="")
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
    response = requests.api.post(url,json={}, headers=headers)
    print(response.text)

if __name__ == "__main__":
    main()

