# New in version 3.8.
# from importlib import metadata
from cycurl._curl import Curl

__title__ = "cycurl"
# __description__ = metadata.metadata("curl_cffi")["Summary"]
# __version__ = metadata.version("curl_cffi")
__description__ = "libcurl cython bindings for Python, with impersonation support"
__version__ = "0.6.2"
__curl_version__ = Curl().version().decode()
