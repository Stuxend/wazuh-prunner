#!/usr/bin/env python3

import boto3
import logging
import argparse
import os
import json
from base64 import b64encode
import requests
import urllib3
import sys

# Configuration
# endpoint = '/api/wazuh/agents?status=disconnected'
protocol = 'https'

# log configuration
logging.basicConfig(stream=sys.stdout)
logging.basicConfig(format="%(asctime)s %(message)s", level=logging.DEBUG)
log = logging.getLogger("wazuh-prunner")
log.setLevel(logging.INFO)


# SETUP SECRETS
secrets_client = boto3.client(
    'secretsmanager', region_name=os.environ['AWS_REGION'])
secret_data = json.loads(secrets_client.get_secret_value(
    SecretId=os.environ['WAZUH_API_SECRET'])['SecretString'])

user = secret_data['USER']
password = secret_data['PASSWORD']

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# handler lambda
def handler(event, context=None):
    log.info("starting wazuh prunner function for event: " + str(event))
    wazuh_time = event.get('wazuh_time')
    endpoint = '/api/wazuh/agents?status=disconnected&older_than='+wazuh_time+'&agents_list=all'
    host = event.get('wazuh_host')
    base_url = f"{protocol}://{host}"
    login_url = f"{base_url}/api/wazuh/security/user/authenticate"
    basic_auth = f"{user}:{password}".encode()
    headers = {'Authorization': f'Basic {b64encode(basic_auth).decode()}'}
    headers['Authorization'] = f'Bearer {get_response(login_url, headers)["data"]["token"]}'
    log.info("initialized the prune function")
    print(base_url + endpoint)
    response = delete_response(base_url + endpoint, headers)
    log.info(json.dumps(response, indent=4, sort_keys=True))


# url get functions
def get_response(url, headers, verify=False):
    """GET API result"""
    request_result = requests.get(url, headers=headers, verify=verify)
    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

# delete agents wazuh
def delete_response(url, headers, verify=False):
    """DELETE API result"""
    try:
        log.info("deleting agents")
        request_result = requests.delete(
            url,  headers=headers, verify=verify)
        if request_result.status_code == 200:
            log.info(json.loads(request_result.content.decode()))
        else:
            log.error(json.loads(request_result.content.decode()))
    except Exception as e:
        log.error("something goes wrong: " + str(e))


def main(argv):
    event = dict()
    event['wazuh_time'] = argv.wazuh_time
    event['wazuh_host'] = argv.wazuh_host

    handler(event)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t', '--wazuh-time'
    )
    parser.add_argument(
        '-U', '--wazuh-host'
    )
    args = parser.parse_args()
    main(args)
