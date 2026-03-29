import platform
import sys

import cycurl


def print_doctor() -> None:
    print("cycurl doctor")
    print("----------------")
    print(f"python: {sys.version.split()[0]}")
    print(f"executable: {sys.executable}")
    print(f"platform: {platform.platform()}")
    print(f"machine: {platform.machine()}")
    print(f"cycurl: {cycurl.__version__}")
    print(f"libcurl: {cycurl.__curl_version__}")
