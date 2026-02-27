# New in version 3.8.
# from importlib import metadata
from cycurl._curl import Curl

__title__ = "cycurl"
# __description__ = metadata.metadata("curl_cffi")["Summary"]
# __version__ = metadata.version("curl_cffi")
__description__ = "libcurl cython bindings for Python, with impersonation support"
__version__ = "0.15.0b4"

def _resolve_curl_version() -> str:
    """Read libcurl version without creating a curl easy handle at import time."""

    return Curl().version().decode()


__curl_version__ = _resolve_curl_version()