from io import BytesIO

from cycurl import *


def preq(conn_primary_ip, conn_local_ip, conn_primary_port, p):
    print("PREREQFUNCTION 咕咕咕", conn_primary_ip, conn_local_ip, conn_primary_port, p)
    return CURL_PREREQFUNC_OK


def progress(dltotal, dlnow, ultotal, ulnow):
    print("progress:", dltotal, dlnow, ultotal, ulnow)
    return 0


def match_cb(pattern, str2):
    print("match_cb:", pattern, str2)
    if pattern in str2:
        return CURL_FNMATCHFUNC_MATCH
    return CURL_FNMATCHFUNC_NOMATCH

def debug_cb(type_, text):
    print("debug_cb:", type_, text)
    return 0

buffer = BytesIO()
c = Curl()
c.setopt(CURLOPT_CUSTOMREQUEST, b"GET")
c.setopt(CURLOPT_URL, b"https://tls.browserleaks.com/json")
c.setopt(CURLOPT_WRITEDATA, buffer)
c.setopt(CURLOPT_PREREQFUNCTION, preq)
c.setopt(CURLOPT_NOPROGRESS, 0)
c.setopt(CURLOPT_XFERINFOFUNCTION, progress)
c.setopt(CURLOPT_FNMATCH_FUNCTION, match_cb)
c.perform()
body = buffer.getvalue()
print("NO impersonate:")
print(body.decode())
print("")


buffer = BytesIO()
c.setopt(CURLOPT_WRITEDATA, buffer)
c.setopt(CURLOPT_URL, b"https://tls.browserleaks.com/json")
c.impersonate("chrome110")
c.setopt(CURLOPT_HTTPHEADER, [b"User-Agent: GUGU"])
c.setopt(CURLOPT_PREREQFUNCTION, preq)
c.setopt(CURLOPT_NOPROGRESS, 0)
c.setopt(CURLOPT_XFERINFOFUNCTION, progress)
c.setopt(CURLOPT_FNMATCH_FUNCTION, match_cb)
c.setopt(CURLOPT_VERBOSE, 1)
c.setopt(CURLOPT_DEBUGFUNCTION, debug_cb)
c.perform()
body = buffer.getvalue()
print("with impersonate:")
print(body.decode())
c.close()
