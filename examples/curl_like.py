from io import BytesIO

from cycurl import *


buffer = BytesIO()
c = Curl()
c.setopt(CURLOPT_CUSTOMREQUEST, b"GET")
c.setopt(CURLOPT_URL, b"https://tls.browserleaks.com/json")
c.setopt(CURLOPT_WRITEDATA, buffer)
c.perform()
body = buffer.getvalue()
print("NO impersonate:")
print(body.decode())
print("")


buffer = BytesIO()
c.setopt(CURLOPT_WRITEDATA, buffer)
c.setopt(CURLOPT_URL, b"https://tls.browserleaks.com/json")
c.impersonate("chrome110")
c.setopt(CURLOPT_HTTPHEADER, [b"User-Agent: Curl/impersonate"])
c.perform()
body = buffer.getvalue()
print("with impersonate:")
print(body.decode())
c.close()
