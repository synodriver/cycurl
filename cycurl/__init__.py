# This line includes _wrapper.so into the wheel
from ._wrapper import ffi, lib

from cycurl._curl import *
from cycurl.__version__ import __title__, __version__, __description__, __curl_version__
