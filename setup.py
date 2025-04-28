# -*- coding: utf-8 -*-
import glob
import os
import platform
import re
import shutil
import sysconfig
from collections import defaultdict

from Cython.Build import cythonize
from Cython.Compiler.Version import version as cython_version
from packaging.version import Version
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

BUILD_ARGS = defaultdict(lambda: ["-O3", "-g0"])

for compiler, args in [
    ("msvc", ["/EHsc", "/DHUNSPELL_STATIC", "/Oi", "/O2", "/Ot"]),
    ("gcc", ["-O3", "-g0", "-Wl,-rpath '$ORIGIN'"]),
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


def get_curl_libraries():
    if uname.system == "Windows":
        return [
            "Crypt32",
            "Secur32",
            "wldap32",
            "Normaliz",
        ]
    else:
        return []


if uname.system == "Windows":
    library_dirs = ["./dep/libcurl-impersonate-v1.0.0rc2.x86_64-win32/lib"]
    extra_objects = []
    for obj in glob.glob("./dep/libcurl-impersonate-v1.0.0rc2.x86_64-win32/lib/*.lib"):
        extra_objects.append(obj)
    extra_objects = [
        i for i in extra_objects if "libcurl.lib" not in i
    ]  # only libcurl_imp is enough
    for file in glob.glob("./dep/libcurl-impersonate-v1.0.0rc2.x86_64-win32/bin/*.dll"):
        shutil.copy(file, "./cycurl")
elif uname.system == "Darwin":
    if platform.machine() == "x86_64":
        library_dirs = ["./dep/libcurl-impersonate-v1.0.0rc2.x86_64-macos"]
        extra_objects = [
            "./dep/libcurl-impersonate-v1.0.0rc2.x86_64-macos/libcurl-impersonate.4.dylib"
        ]
        for file in glob.glob(
            "./dep/libcurl-impersonate-v1.0.0rc2.x86_64-macos/*.dylib"
        ):
            shutil.copy(file, "./cycurl")
    else:
        library_dirs = ["./dep/libcurl-impersonate-v1.0.0rc2.arm64-macos"]
        extra_objects = [
            "./dep/libcurl-impersonate-v1.0.0rc2.arm64-macos/libcurl-impersonate.4.dylib"
        ]
        for file in glob.glob(
            "./dep/libcurl-impersonate-v1.0.0rc2.arm64-macos/*.dylib"
        ):
            shutil.copy(file, "./cycurl")
else:
    library_dirs = ["./dep/libcurl-impersonate-v1.0.0rc2.x86_64-linux-gnu"]
    extra_objects = [
        "./dep/libcurl-impersonate-v1.0.0rc2.x86_64-linux-gnu/libcurl-impersonate.so.4.8.0"
    ]
    for file in glob.glob("./dep/libcurl-impersonate-v1.0.0rc2.x86_64-linux-gnu/*.so"):
        shutil.copy(file, "./cycurl")
    # library_diexit(rs = ["./dep/linux_v0.6.0-alpha.1.x86_64-linux-gnu"]
    # extra_objects = [
    #     "./dep/linux_v0.6.0-alpha.1.x86_64-linux-gnu/libcurl-impersonate.so.4.8.0"
    # ]

if sysconfig.get_config_var("Py_GIL_DISABLED"):
    print("build nogil")
    defined_macros = [
        ("Py_GIL_DISABLED", "1"),
    ]  # ("CYTHON_METH_FASTCALL", "1"), ("CYTHON_VECTORCALL",  1)]
else:
    defined_macros = []

extensions = [
    Extension(
        "cycurl._curl",
        ["cycurl/_curl.pyx", "ffi/shim.c"],
        libraries=get_curl_libraries(),
        include_dirs=[
            f"./dep/curl-8.13.0/include",
            "ffi",
        ],
        library_dirs=library_dirs,
        extra_objects=extra_objects,
        extra_compile_args=(
            ["-Wno-implicit-function-declaration"] if uname.system == "Darwin" else []
        ),
        extra_link_args=(["-lstdc++"] if uname.system != "Windows" else []),
        define_macros=defined_macros,
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


packages = ["cycurl"]

compiler_directives = {
    "cdivision": True,
    "embedsignature": True,
    "boundscheck": False,
    "wraparound": False,
}


if Version(cython_version) >= Version("3.1.0a0"):
    compiler_directives["freethreading_compatible"] = True


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
        setup_requires=["cython>=3.0.10"],
        install_requires=["certifi>=2024.2.2"],
        extra_requires={
            "readability-lxml>": ["readability-lxml>=0.8.1"],
            "markdownify": ["markdownify>=1.1.0"],
            "lxml_html_clean": ["lxml_html_clean"],
        },
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
            "Programming Language :: Python :: 3.13",
            "Programming Language :: Python :: Implementation :: CPython",
        ],
        include_package_data=True,
        zip_safe=False,
        cmdclass={"build_ext": build_ext_compiler_check},
        ext_modules=cythonize(
            extensions,
            compiler_directives=compiler_directives,
        ),
    )


if __name__ == "__main__":
    main()
