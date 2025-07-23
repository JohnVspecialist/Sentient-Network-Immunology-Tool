#!/usr/bin/python3

import requests as r 

URL="http://example.com"

response = r.get(URL)
print(response.status_code)