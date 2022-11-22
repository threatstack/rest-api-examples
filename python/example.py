# Copyright (c) 2018-2022 F5, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mohawk import Sender
import requests
import os
import sys


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

BASE_PATH = 'https://' + HOST
URI_PATH = '/help/hawk/self-test'

credentials = {
    'id': USER_ID,
    'key': API_KEY,
    'algorithm': 'sha256'
}
URL = BASE_PATH + URI_PATH
sender = Sender(credentials, URL, "GET", always_hash_content=False, ext=ORGANIZATION_ID)

response = requests.get(URL, headers={'Authorization': sender.request_header})
print(response.text)
# Note a warning is logged out during the authenticate call:
# seen_nonce was None; not checking nonce. You may be vulnerable to replay attacks
# This is not an issue because the nonce is randomly generated above and a different
# nonce is used for each request.
sender.accept_response(response.headers['Server-Authorization'],
                       content=response.text,
                       content_type=response.headers['Content-Type'])

# accept_response will throw if the response is not authentic
# after this call we know the response is authentic
print('Response is authentic')
