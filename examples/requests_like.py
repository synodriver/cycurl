from cycurl import requests
from cycurl import CURLOPT_RESOLVE

r = requests.get("https://tls.browserleaks.com/json")
print("No impersonation", r.json())


r = requests.get("https://tls.browserleaks.com/json", impersonate="chrome101")
print("With impersonation", r.json())


s = requests.Session(impersonate="chrome110")
r = s.get("https://tls.browserleaks.com/json")
print("With impersonation", r.json())

s = requests.Session(impersonate="firefox133")
r = s.get("https://tls.browserleaks.com/json")
print("With impersonation", r.json())

s = requests.Session(impersonate="firefox133")
s.curl.setopt(CURLOPT_RESOLVE, ["example.com:1313:127.0.0.1"])
r = s.get("http://example.com:1313")
print("With impersonation", r.text)