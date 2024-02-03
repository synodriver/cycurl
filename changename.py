import os
import platform

for f in os.listdir("dist"):
    if "linux" in f:
        os.rename(
            os.path.join("dist", f),
            os.path.join("dist", f.replace("linux", "manylinux2014")),
        )
    elif "macosx" in f:
        if platform.machine() == "x86_64":
            os.rename(
                os.path.join("dist", f),
                os.path.join("dist", f.replace("universal2", "x86_64")),
            )
        else:
            os.rename(
                os.path.join("dist", f),
                os.path.join("dist", f.replace("universal2", "arm64")),
            )
