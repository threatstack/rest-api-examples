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
URI_PATH = '/v2/rulesets/' + RULESET_ID + '/rules'

credentials = {
    'id': USER_ID,
    'key': API_KEY,
    'algorithm': 'sha256'
}
URL = BASE_PATH + URI_PATH

rule_data = {
    "name": "API Test Rule: Sudo Usage",
    "title": "API Test Rule: Sudo Usage",
    "type": "host",
    "severityOfAlerts": 2,
    "alertDescription": "This rule was created as a test of the Threat Stack REST API. It monitors for usage of sudo",
    "aggregateFields": ["user", "session"],
    "filter": "command = 'sudo'",
    "window": 3600,
    "threshold": 1,
    "suppressions": ["user = 'alice' OR user = 'bob'"],
    "enabled": True
}

post_data = json.dumps(rule_data)
sender = Sender(credentials, URL, "POST", always_hash_content=False, ext=ORGANIZATION_ID, content = post_data, content_type = 'application/json')

response = requests.post(URL, headers={'Authorization': sender.request_header, 'Content-Type': 'application/json'}, data = post_data)
print(response.status_code)
print(json.dumps(response.json(), indent = 2))
