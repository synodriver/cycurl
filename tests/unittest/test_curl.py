import base64
import json
from io import BytesIO
from typing import cast

import pytest

from cycurl import *

#######################################################################################
# testing setopt
#######################################################################################


def test_get(server):
    c = Curl()
    c.setopt(CURLOPT_URL, str(server.url).encode())
    c.perform()


def test_post(server):
    c = Curl()
    url = str(server.url.copy_with(path="/echo_body"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_POST, 1)
    c.setopt(CURLOPT_POSTFIELDS, b"foo=bar")
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    assert buffer.getvalue() == b"foo=bar"


def test_put(server):
    c = Curl()
    c.setopt(CURLOPT_URL, str(server.url).encode())
    c.setopt(CURLOPT_CUSTOMREQUEST, b"PUT")
    c.perform()


def test_delete(server):
    c = Curl()
    c.setopt(CURLOPT_URL, str(server.url).encode())
    c.setopt(CURLOPT_CUSTOMREQUEST, b"DELETE")
    c.perform()


def test_post_data_with_size(server):
    c = Curl()
    url = str(server.url.copy_with(path="/echo_body"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_CUSTOMREQUEST, b"POST")
    c.setopt(CURLOPT_POSTFIELDS, b"\0" * 7)
    c.setopt(CURLOPT_POSTFIELDSIZE, 7)
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    assert buffer.getvalue() == b"\0" * 7


def test_headers(server):
    c = Curl()
    url = str(server.url.copy_with(path="/echo_headers"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_HTTPHEADER, [b"Foo: bar"])
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    headers = json.loads(buffer.getvalue().decode())
    assert headers["Foo"][0] == "bar"

    # https://github.com/lexiforest/curl_cffi/issues/16
    c.setopt(CURLOPT_HTTPHEADER, [b"Foo: baz"])
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    headers = json.loads(buffer.getvalue().decode())
    assert headers["Foo"][0] == "baz"


def test_proxy_headers(server):
    # XXX only tests that proxy header is not present for target server, should add
    # tests that verifies proxy headers are sent to proxy server.
    c = Curl()
    url = str(server.url.copy_with(path="/echo_headers"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_PROXYHEADER, [b"Foo: bar"])
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    headers = json.loads(buffer.getvalue().decode())
    assert "Foo" not in headers

    # https://github.com/lexiforest/curl_cffi/issues/16
    c.setopt(CURLOPT_PROXYHEADER, [b"Foo: baz"])
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    headers = json.loads(buffer.getvalue().decode())
    assert "Foo" not in headers


def test_write_function_memory_leak(server):
    c = Curl()
    for _ in range(10):
        url = str(server.url.copy_with(path="/echo_headers"))
        c.setopt(CURLOPT_URL, url.encode())
        c.setopt(CURLOPT_HTTPHEADER, [b"Foo: bar"])
        buffer = BytesIO()
        c.setopt(CURLOPT_WRITEDATA, buffer)
        c.perform()
    assert c._write_handle is None


def test_write_function(server):
    c = Curl()
    url = str(server.url.copy_with(path="/echo_body"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_POST, 1)
    c.setopt(CURLOPT_POSTFIELDS, b"foo=bar")

    buffer = BytesIO()

    def write(data: bytes):
        buffer.write(data)
        return len(data)

    c.setopt(CURLOPT_WRITEFUNCTION, write)
    c.perform()
    assert buffer.getvalue() == b"foo=bar"


def test_cookies(server):
    c = Curl()
    url = str(server.url.copy_with(path="/echo_cookies"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_COOKIE, b"foo=bar")
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    cookies = json.loads(buffer.getvalue().decode())
    # print(cookies)
    assert cookies["foo"] == "bar"


def test_auth(server):
    c = Curl()
    url = str(server.url.copy_with(path="/echo_headers"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_USERNAME, b"foo")
    c.setopt(CURLOPT_PASSWORD, b"bar")
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    headers = json.loads(buffer.getvalue().decode())
    assert (
        headers["Authorization"][0] == f"Basic {base64.b64encode(b'foo:bar').decode()}"
    )


def test_timeout(server):
    c = Curl()
    url = str(server.url.copy_with(path="/slow_response"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_TIMEOUT_MS, 100)
    with pytest.raises(CurlError, match=r"curl: \(28\)"):
        c.perform()


def test_repeated_headers_after_error(server):
    c = Curl()
    url = str(server.url.copy_with(path="/slow_response"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_TIMEOUT_MS, 100)
    c.setopt(CURLOPT_HTTPHEADER, [b"Foo: bar"])
    with pytest.raises(CurlError, match=r"curl: \(28\)"):
        c.perform()

    # another request
    url = str(server.url.copy_with(path="/echo_headers"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_HTTPHEADER, [b"Foo: bar"])
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    headers = json.loads(buffer.getvalue().decode())
    assert len(headers["Foo"]) == 1
    # print(headers)


def test_follow_redirect(server):
    c = Curl()
    url = str(server.url.copy_with(path="/redirect_301"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_FOLLOWLOCATION, 1)
    c.perform()
    assert c.getinfo(CURLINFO_RESPONSE_CODE) == 200


def test_not_follow_redirect(server):
    c = Curl()
    url = str(server.url.copy_with(path="/redirect_301"))
    c.setopt(CURLOPT_URL, url.encode())
    c.perform()
    assert c.getinfo(CURLINFO_RESPONSE_CODE) == 301


def test_http_proxy_changed_path(server):
    c = Curl()
    proxy_url = str(server.url).rstrip("/")
    print("proxy url", proxy_url)
    c.setopt(CURLOPT_URL, b"http://example.org")
    c.setopt(CURLOPT_PROXY, proxy_url.encode())
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    rsp = json.loads(buffer.getvalue().decode())
    assert rsp["Hello"] == "http_proxy!"


def test_https_proxy_using_connect(server):
    c = Curl()
    proxy_url = str(server.url)
    c.setopt(CURLOPT_URL, b"https://example.org")
    c.setopt(CURLOPT_PROXY, proxy_url.encode())
    c.setopt(CURLOPT_HTTPPROXYTUNNEL, 1)
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    with pytest.raises(CurlError, match=r"curl: \(35\)"):
        c.perform()


def test_verify(https_server):
    c = Curl()
    url = str(https_server.url)
    c.setopt(CURLOPT_URL, url.encode())
    with pytest.raises(CurlError, match="SSL certificate problem"):
        c.perform()


def test_verify_false(https_server):
    c = Curl()
    url = str(https_server.url)
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_SSL_VERIFYPEER, 0)
    c.setopt(CURLOPT_SSL_VERIFYHOST, 0)
    c.perform()


def test_referer(server):
    c = Curl()
    url = str(server.url.copy_with(path="/echo_headers"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_REFERER, b"http://example.org")
    buffer = BytesIO()
    c.setopt(CURLOPT_WRITEDATA, buffer)
    c.perform()
    headers = json.loads(buffer.getvalue().decode())
    assert headers["Referer"][0] == "http://example.org"


#######################################################################################
# testing getinfo
#######################################################################################


def test_effective_url(server):
    c = Curl()
    url = str(server.url.copy_with(path="/redirect_301"))
    c.setopt(CURLOPT_URL, url.encode())
    c.setopt(CURLOPT_FOLLOWLOCATION, 1)
    c.perform()
    assert c.getinfo(CURLINFO_EFFECTIVE_URL) == str(server.url).encode()


def test_status_code(server):
    c = Curl()
    url = str(server.url)
    c.setopt(CURLOPT_URL, url.encode())
    c.perform()
    assert c.getinfo(CURLINFO_RESPONSE_CODE) == 200


def test_response_headers(server):
    c = Curl()
    url = str(server.url.copy_with(path="/set_headers"))
    c.setopt(CURLOPT_URL, url.encode())
    buffer = BytesIO()
    c.setopt(CURLOPT_HEADERDATA, buffer)
    c.perform()
    headers = buffer.getvalue().decode()
    for line in headers.splitlines():
        if line.startswith("x-test"):
            assert line.startswith("x-test: test")


def test_response_cookies(server):
    c = Curl()
    url = str(server.url.copy_with(path="/set_cookies"))
    c.setopt(CURLOPT_URL, url.encode())
    buffer = BytesIO()
    c.setopt(CURLOPT_HEADERDATA, buffer)
    c.perform()
    headers = buffer.getvalue()
    cookie = c.parse_cookie_headers(headers.splitlines())
    for name, morsel in cookie.items():
        if name == "foo":
            assert morsel.value == "bar"


def test_elapsed(server):
    c = Curl()
    url = str(server.url)
    c.setopt(CURLOPT_URL, url.encode())
    c.perform()
    assert cast(int, c.getinfo(CURLINFO_TOTAL_TIME)) > 0


def test_reason(server):
    c = Curl()
    url = str(server.url)
    c.setopt(CURLOPT_URL, url.encode())
    buffer = BytesIO()
    c.setopt(CURLOPT_HEADERDATA, buffer)
    c.perform()
    headers = buffer.getvalue()
    headers = headers.splitlines()
    assert c.get_reason_phrase(headers[0]) == b"OK"


def test_resolve(server):
    c = Curl()
    url = "http://example.com:8000"
    c.setopt(CURLOPT_RESOLVE, ["example.com:8000:127.0.0.1"])
    c.setopt(CURLOPT_URL, url)
    c.perform()


def test_duphandle(server):
    c = Curl()
    c.setopt(CURLOPT_URL, str(server.url.copy_with(path="/redirect_loop")).encode())
    c.setopt(CURLOPT_FOLLOWLOCATION, 1)
    c.setopt(CURLOPT_MAXREDIRS, 2)
    c = c.duphandle()
    with pytest.raises(CurlError):
        c.perform()
