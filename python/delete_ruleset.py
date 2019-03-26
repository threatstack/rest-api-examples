from mohawk import Sender
import requests
import os
import sys
import json


def get_or_throw(key_name):
    res = os.getenv(key_name, None)
    if res is None:
        print("Environment variable '" + key_name + "' is required.")
        sys.exit(1)
    return res


HOST = os.getenv("TS_HOST", 'api.threatstack.com')
USER_ID = get_or_throw("TS_USER_ID")
ORGANIZATION_ID = get_or_throw("TS_ORGANIZATION_ID")
API_KEY = get_or_throw("TS_API_KEY")

RULESET_ID = get_or_throw("TS_RULESET_ID")

BASE_PATH = 'https://' + HOST
URI_PATH = '/v2/rulesets/' + RULESET_ID

credentials = {
    'id': USER_ID,
    'key': API_KEY,
    'algorithm': 'sha256'
}
URL = BASE_PATH + URI_PATH

ruleset_data = {
    'server_ids': []
}

delete_data = json.dumps(ruleset_data)
sender = Sender(credentials, URL, "DELETE", always_hash_content=False, ext=ORGANIZATION_ID, content = delete_data, content_type = 'application/json')

response = requests.delete(URL, headers={'Authorization': sender.request_header, 'Content-Type': 'application/json'})
print(response.status_code)
print(json.dumps(response.json(), indent = 2))
