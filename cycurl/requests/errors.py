# for compatibility with 0.5.x

__all__ = ["CurlError", "RequestsError", "CookieConflict", "SessionClosed"]

from cycurl._curl import CurlError
from cycurl.requests.exceptions import CookieConflict
from cycurl.requests.exceptions import RequestException as RequestsError
from cycurl.requests.exceptions import SessionClosed
