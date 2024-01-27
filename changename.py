import os

for f in os.listdir("dist"):
    if "linux" in f:
        os.rename(
            os.path.join("dist", f),
            os.path.join("dist", f.replace("linux", "manylinux2014")),
        )
