# Apache 2.0 License
# Vendored from https://github.com/psf/requests/blob/main/src/requests/exceptions.py
# With our own addtions

import json
from typing import Literal, Union

from cycurl._curl import *


# Note IOError is an alias of OSError in Python 3.x
class RequestException(CurlError, OSError):
    """Base exception for cycurl.requests package"""

    def __init__(
        self, msg, code: Union[int, Literal[0]] = 0, response=None, *args, **kwargs
    ):
        super().__init__(msg, code, *args, **kwargs)
        self.response = response


class CookieConflict(RequestException):
    """Same cookie exists for different domains."""


class SessionClosed(RequestException):
    """The session has already been closed."""


class ImpersonateError(RequestException):
    """The impersonate config was wrong or impersonate failed."""


# not used
class InvalidJSONError(RequestException):
    """A JSON error occurred. not used"""


# not used
class JSONDecodeError(InvalidJSONError, json.JSONDecodeError):
    """Couldn't decode the text into json. not used"""


class HTTPError(RequestException):
    """An HTTP error occurred."""


class IncompleteRead(HTTPError):
    """Incomplete read of content"""


class ConnectionError(RequestException):
    """A Connection error occurred."""


class DNSError(ConnectionError):
    """Could not resolve"""


class ProxyError(RequestException):
    """A proxy error occurred."""


class SSLError(ConnectionError):
    """An SSL error occurred."""


class CertificateVerifyError(SSLError):
    """Raised when certificate validated has failed"""


class Timeout(RequestException):
    """The request timed out."""


# not used
class ConnectTimeout(ConnectionError, Timeout):
    """The request timed out while trying to connect to the remote server.

    Requests that produced this error are safe to retry.

    not used
    """


# not used
class ReadTimeout(Timeout):
    """The server did not send any data in the allotted amount of time. not used"""


# not used
class URLRequired(RequestException):
    """A valid URL is required to make a request. not used"""


class TooManyRedirects(RequestException):
    """Too many redirects."""


# not used
class MissingSchema(RequestException, ValueError):
    """The URL scheme (e.g. http or https) is missing. not used"""


class InvalidSchema(RequestException, ValueError):
    """The URL scheme provided is either invalid or unsupported. not used"""


class InvalidURL(RequestException, ValueError):
    """The URL provided was somehow invalid."""


# not used
class InvalidHeader(RequestException, ValueError):
    """The header value provided was somehow invalid. not used"""


# not used
class InvalidProxyURL(InvalidURL):
    """The proxy URL provided is invalid. not used"""


# not used
class ChunkedEncodingError(RequestException):
    """The server declared chunked encoding but sent an invalid chunk. not used"""


# not used
class ContentDecodingError(RequestException):
    """Failed to decode response content. not used"""


# not used
class StreamConsumedError(RequestException, TypeError):
    """The content for this response was already consumed. not used"""


# does not support
class RetryError(RequestException):
    """Custom retries logic failed. not used"""


# not used
class UnrewindableBodyError(RequestException):
    """Requests encountered an error when trying to rewind a body. not used"""


class InterfaceError(RequestException):
    """A specified outgoing interface could not be used."""


# Warnings


# TODO use this warning as a base
class RequestsWarning(Warning):
    """Base warning for Requests. not used"""


# not used
class FileModeWarning(RequestsWarning, DeprecationWarning):
    """A file was opened in text mode, but Requests determined its binary length. not used"""


# not used
class RequestsDependencyWarning(RequestsWarning):
    """An imported dependency doesn't match the expected version range."""


CODE2ERROR = {
    0: RequestException,
    CURLE_UNSUPPORTED_PROTOCOL: InvalidSchema,
    CURLE_URL_MALFORMAT: InvalidURL,
    CURLE_COULDNT_RESOLVE_PROXY: ProxyError,
    CURLE_COULDNT_RESOLVE_HOST: DNSError,
    CURLE_COULDNT_CONNECT: ConnectionError,
    CURLE_WEIRD_SERVER_REPLY: ConnectionError,
    CURLE_REMOTE_ACCESS_DENIED: ConnectionError,
    CURLE_HTTP2: HTTPError,
    CURLE_HTTP_RETURNED_ERROR: HTTPError,
    CURLE_WRITE_ERROR: RequestException,
    CURLE_READ_ERROR: RequestException,
    CURLE_OUT_OF_MEMORY: RequestException,
    CURLE_OPERATION_TIMEDOUT: Timeout,
    CURLE_SSL_CONNECT_ERROR: SSLError,
    CURLE_INTERFACE_FAILED: InterfaceError,
    CURLE_TOO_MANY_REDIRECTS: TooManyRedirects,
    CURLE_UNKNOWN_OPTION: RequestException,
    CURLE_SETOPT_OPTION_SYNTAX: RequestException,
    CURLE_GOT_NOTHING: ConnectionError,
    CURLE_SSL_ENGINE_NOTFOUND: SSLError,
    CURLE_SSL_ENGINE_SETFAILED: SSLError,
    CURLE_SEND_ERROR: ConnectionError,
    CURLE_RECV_ERROR: ConnectionError,
    CURLE_SSL_CERTPROBLEM: SSLError,
    CURLE_SSL_CIPHER: SSLError,
    CURLE_PEER_FAILED_VERIFICATION: CertificateVerifyError,
    CURLE_BAD_CONTENT_ENCODING: HTTPError,
    CURLE_SSL_ENGINE_INITFAILED: SSLError,
    CURLE_SSL_CACERT_BADFILE: SSLError,
    CURLE_SSL_CRL_BADFILE: SSLError,
    CURLE_SSL_ISSUER_ERROR: SSLError,
    CURLE_SSL_PINNEDPUBKEYNOTMATCH: SSLError,
    CURLE_SSL_INVALIDCERTSTATUS: SSLError,
    CURLE_HTTP2_STREAM: HTTPError,
    CURLE_HTTP3: HTTPError,
    CURLE_QUIC_CONNECT_ERROR: ConnectionError,
    CURLE_PROXY: ProxyError,
    CURLE_SSL_CLIENTCERT: SSLError,
    CURLE_ECH_REQUIRED: SSLError,
    CURLE_PARTIAL_FILE: IncompleteRead,
}


# credits: https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/networking/_curlcffi.py#L241
# Unlicense
def code2error(code: Union[int, Literal[0]], msg: str):
    if code == CURLE_RECV_ERROR and "CONNECT" in msg:
        return ProxyError
    return CODE2ERROR.get(code, RequestException)
