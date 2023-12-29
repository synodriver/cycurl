# -*- coding: utf-8 -*-
import os
import platform
import re
import shutil
from collections import defaultdict

from Cython.Build import cythonize
from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext

BUILD_ARGS = defaultdict(lambda: ["-O3", "-g0"])

for compiler, args in [
    ("msvc", ["/EHsc", "/DHUNSPELL_STATIC", "/Oi", "/O2", "/Ot"]),
    ("gcc", ["-O3", "-g0"]),
]:
    BUILD_ARGS[compiler] = args

uname = platform.uname()


class build_ext_compiler_check(build_ext):
    def build_extensions(self):
        compiler = self.compiler.compiler_type
        args = BUILD_ARGS[compiler]
        for ext in self.extensions:
            ext.extra_compile_args.extend(args)
        super().build_extensions()


if uname.system == "Windows":
    library_dirs = ["./dep/win"]
    extra_objects = ["./dep/win/libcurl.lib"]
    shutil.copy("./dep/win/libcurl.dll", "./cycurl")
elif uname.system == "Darwin":
    library_dirs = ["./dep/macos_v0.6.0-alpha.1.x86_64"]
    extra_objects = ["./dep/macos_v0.6.0-alpha.1.x86_64/libcurl-impersonate-chrome.a"]
else:
    library_dirs = ["./dep/linux_latest/chromelibs"]
    extra_objects = ["./dep/linux_latest/chromelibs/libcurl-impersonate-chrome.a"]

extensions = [
    Extension(
        "cycurl._curl",
        ["cycurl/_curl.pyx", "cycurl/ffi/shim.c"],
        include_dirs=[
            f"./dep/curl-8.1.1/include",
            os.path.join(os.path.dirname(__file__), "cycurl", "ffi"),
        ],
        library_dirs=library_dirs,
        extra_objects=extra_objects,
        extra_compile_args=(
            ["-Wno-implicit-function-declaration"] if uname.system == "Darwin" else []
        ),
    ),
]


def get_dis():
    with open("README.md", "r", encoding="utf-8") as f:
        return f.read()


def get_version() -> str:
    path = os.path.join(
        os.path.abspath(os.path.dirname(__file__)), "cycurl", "__version__.py"
    )
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    result = re.findall(r"(?<=__version__ = \")\S+(?=\")", data)
    return result[0]


packages = find_packages(exclude=("test", "tests.*", "test*"))


def main():
    version: str = get_version()
    dis = get_dis()
    setup(
        name="cycurl",
        version=version,
        url="https://github.com/synodriver/cycurl",
        packages=packages,
        keywords=["libcurl", "curl"],
        description="Ultra fast libcurl wrapper with impersonate",
        long_description_content_type="text/markdown",
        long_description=dis,
        author="synodriver",
        author_email="diguohuangjiajinweijun@gmail.com",
        python_requires=">=3.6",
        setup_requires=["cython>=3"],
        license="BSD",
        classifiers=[
            "Development Status :: 4 - Beta",
            "Operating System :: OS Independent",
            "License :: OSI Approved :: BSD License",
            "Programming Language :: C",
            "Programming Language :: Cython",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
            "Programming Language :: Python :: Implementation :: CPython",
        ],
        include_package_data=True,
        zip_safe=False,
        cmdclass={"build_ext": build_ext_compiler_check},
        ext_modules=cythonize(
            extensions,
            compiler_directives={
                "cdivision": True,
                "embedsignature": True,
                "boundscheck": False,
                "wraparound": False,
            },
        ),
    )


if __name__ == "__main__":
    main()
