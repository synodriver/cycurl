# cython: language_level=3
# cython: cdivision=True
from asyncio.windows_events import NULL
from pathlib import Path

cimport cython
from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_GET_SIZE
from cpython.float cimport PyFloat_FromDouble
from cpython.long cimport PyLong_FromLong
from cpython.mem cimport PyMem_Free, PyMem_Malloc
from cpython.pycapsule cimport PyCapsule_CheckExact, PyCapsule_GetPointer, PyCapsule_New
from cpython.unicode cimport PyUnicode_FromString, PyUnicode_AsUTF8
from libc.stdint cimport int64_t, uint8_t, uintptr_t
from libc.stdio cimport fflush, fprintf, fwrite, stderr
from libc.string cimport memcpy

include "consts.pxi"
include "utils.pxi"

import asyncio
import locale
import re
import struct
import ssl
import sys
from contextlib import suppress
from http.cookies import SimpleCookie
from weakref import WeakKeyDictionary, WeakSet

import os

import certifi

cpdef str _default_cacert():
    # 1. Explicit env var overrides
    for env_var in ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE"):
        path = os.environ.get(env_var)
        if path and os.path.exists(path):
            return path

    # 2. Python's CA bundle
    defaults = ssl.get_default_verify_paths()
    if defaults.cafile and os.path.exists(defaults.cafile):
        return defaults.cafile

    # 3. Fallback to certifi
    return certifi.where()


DEFAULT_CACERT = _default_cacert()
REASON_PHRASE_RE = re.compile(rb"HTTP/\d\.\d [0-9]{3} (.*)")
STATUS_LINE_RE = re.compile(rb"HTTP/(\d\.\d) ([0-9]{3}) (.*)")


class CurlError(Exception):
    """Base exception for cycurl package"""

    def __init__(self, msg, code: int = 0, *args, **kwargs):
        super().__init__(msg, *args, **kwargs)
        self.code = code

cdef class _CallbackContext:
    cdef public object callback
    cdef public BaseException exception
    def __init__(self, object callback):
        self.callback = callback
        self.exception = None

cdef int debug_function(curl.CURL *curl_, int type_, char *data, size_t size, void *clientp) with gil:
    """ffi callback for curl debug info"""
    cdef _CallbackContext context = <_CallbackContext>clientp
    if context.exception is not None:
        return 0
    cdef object callback = context.callback
    cdef bytes text = <bytes>data[:size]
    try:
        return callback(type_, text)
    except BaseException as e:
        context.exception = e
        return 0

cdef inline str bytes_to_hex(bytes b, bint uppercase = False):
    """
    Convert a bytes object to a space-separated hex string, e.g. "0a ff 3c".
    If uppercase=True, letters will be A–F instead of a–f.
    """
    fmt = "{:02X}" if uppercase else "{:02x}"
    return " ".join(fmt.format(byte) for byte in b)


def debug_function_default(type_: int, data: bytes) -> None:
    PREFIXES = {
        curl.CURLINFO_TEXT:          "*",
        curl.CURLINFO_HEADER_IN:     "<",
        curl.CURLINFO_HEADER_OUT:    ">",
        curl.CURLINFO_DATA_IN:       "< DATA",
        curl.CURLINFO_DATA_OUT:      "> DATA",
        curl.CURLINFO_SSL_DATA_IN:   "< SSL",
        curl.CURLINFO_SSL_DATA_OUT:  "> SSL",
    }
    MAX_SHOW_BYTES = 40
    prefix = PREFIXES.get(type_, "*")

    # always show ssl data in binary format
    if type_ == curl.CURLINFO_SSL_DATA_IN or type_ == curl.CURLINFO_SSL_DATA_OUT:
        hex_str = bytes_to_hex(data[:MAX_SHOW_BYTES])
        postfix = "" if len(data) <= MAX_SHOW_BYTES else "..."
        sys.stderr.write(f"{prefix} [{len(data)} bytes]: {hex_str}{postfix}\n")
    else:
        try:
            text = data.decode("utf-8")
            sys.stderr.write(f"{prefix} {text}")
            if type_ != curl.CURLINFO_TEXT and type_ != curl.CURLINFO_HEADER_IN and type_ != curl.CURLINFO_HEADER_OUT:
                sys.stderr.write("\n")
        except UnicodeDecodeError:
            # Fallback to hex representation of first MAX_SHOW_BYTES bytes
            hex_str = bytes_to_hex(data[:MAX_SHOW_BYTES])
            postfix = "" if len(data) <= MAX_SHOW_BYTES else "..."
            sys.stderr.write(f"{prefix} [{len(data)} bytes]: {hex_str}{postfix}\n")


cdef size_t buffer_callback(char *ptr, size_t size, size_t nmemb, void *userdata) with gil:
    """ffi callback for curl write function, directly writes to a buffer"""
    cdef size_t total = size*nmemb
    cdef _CallbackContext context = <_CallbackContext>userdata
    cdef object stream = context.callback
    try:
        stream.write(<bytes>ptr[:total])
    except BaseException as e:
        context.exception = e
        return curl.CURL_WRITEFUNC_ERROR
    return total

cdef size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) with gil:
    """ffi callback for curl write function, calls the callback python function"""
    cdef:
        size_t total
        _CallbackContext context
        object callback
        ssize_t wrote
    total = size*nmemb
    context = <_CallbackContext>userdata
    callback = context.callback
    try:
        wrote = callback(<bytes>ptr[:total])
    except BaseException as e:
        context.exception = e
        return curl.CURL_WRITEFUNC_ERROR
    if <unsigned int>wrote == curl.CURL_WRITEFUNC_PAUSE or <unsigned int>wrote == curl.CURL_WRITEFUNC_ERROR:
        return wrote
    # should make this an exception in future versions
    if wrote != total:
        warnings.warn("Wrote bytes != received bytes.", CurlWarning, stacklevel=2)
    return total

cdef size_t read_buffer_callback(char *buffer, size_t size, size_t nitems, void *userdata) except? 268435456 with gil:
    cdef size_t total = size * nitems
    cdef _CallbackContext context = <_CallbackContext>userdata
    cdef object stream = context.callback
    cdef bytes ret
    cdef size_t read_size
    cdef const char * ret_ptr
    try:
        ret = stream.read(total)
        read_size = PyBytes_GET_SIZE(ret)
        if read_size > total:
            raise CurlError(
                f"Read callback returned {read_size} bytes, but only {total} bytes are allowed.")  # noqa: E501
        ret_ptr = <const char *> ret
        memcpy(buffer, ret_ptr, read_size)
        return read_size
    except BaseException as e:
        context.exception = e
        return curl.CURL_READFUNC_ABORT


cdef size_t read_callback(char *buffer, size_t size, size_t nitems, void *userdata) except? 268435456 with gil:
    cdef:
        size_t total
        size_t read_size
        _CallbackContext context
        object callback
        bytes ret
        const char* ret_ptr
    context = <_CallbackContext>userdata
    callback = context.callback
    total = size * nitems # numbytes
    try:
        ret = callback(total)
        read_size = PyBytes_GET_SIZE(ret)
        if read_size > total: # stream end
            raise CurlError(
                f"Read callback returned {read_size} bytes, but only {total} bytes are allowed."  # noqa: E501
            )
        ret_ptr = <const char*>ret
        memcpy(buffer, ret_ptr, read_size)
        return read_size
    except BaseException as e:
        context.exception = e
        return curl.CURL_READFUNC_ABORT

cdef int seek_callback(void *clientp, curl.curl_off_t offset, int origin) except? 2 with gil:
    cdef _CallbackContext context = <_CallbackContext>clientp
    cdef object callback = context.callback
    try:
        callback(offset, origin)
        return curl.CURL_SEEKFUNC_OK
    except (AttributeError, OSError):
        return curl.CURL_SEEKFUNC_CANTSEEK
    except BaseException as e:
        context.exception = e
        return curl.CURL_SEEKFUNC_FAIL

cdef int seek_buffer_callback(void *clientp, curl.curl_off_t offset, int origin) except? 2 with gil:
    cdef _CallbackContext context = <_CallbackContext>clientp
    cdef object stream = context.callback
    try:
        stream.seek(offset, origin)
        return curl.CURL_SEEKFUNC_OK
    except (AttributeError, OSError):
        return curl.CURL_SEEKFUNC_CANTSEEK
    except BaseException as e:
        context.exception = e
        return curl.CURL_SEEKFUNC_FAIL


cdef int trailer_callback(curl.curl_slist ** list, void *userdata) except? 1 with gil:
    cdef _CallbackContext context = <_CallbackContext>userdata
    cdef object callback = context.callback
    try:
        trailers = callback()
        for tr in trailers:
            list[0] = curl.curl_slist_append(list[0], <const char*>tr)
        return curl.CURL_TRAILERFUNC_OK
    except BaseException as e:
        context.exception = e
        return curl.CURL_TRAILERFUNC_ABORT

cdef int prereq_callback(void *clientp,
                    char *conn_primary_ip,
                    char *conn_local_ip,
                    int conn_primary_port,
                    int conn_local_port) except? 1 with gil:
    cdef _CallbackContext context = <_CallbackContext>clientp
    cdef object callback = context.callback
    try:
        return callback(PyUnicode_FromString(conn_primary_ip),
                    PyUnicode_FromString(conn_local_ip),
                    conn_primary_port,
                    conn_local_port)
    except BaseException as e:
        context.exception = e
        return curl.CURL_PREREQFUNC_ABORT

cdef int xferinfo_callback(void *clientp,
                      curl.curl_off_t dltotal,
                      curl.curl_off_t dlnow,
                      curl.curl_off_t ultotal,
                      curl.curl_off_t ulnow) except? 1 with gil:
    cdef _CallbackContext context = <_CallbackContext>clientp
    cdef object callback = context.callback
    try:
        return callback(dltotal, dlnow, ultotal, ulnow)
    except BaseException as e:
        context.exception = e
        return -1

cdef int fnmatch_callback(void *clientp,
                     const char *pattern,
                     const char *string) except? 2 with gil:
    cdef _CallbackContext context = <_CallbackContext>clientp
    cdef object callback = context.callback
    try:
        return callback(PyUnicode_FromString(pattern), PyUnicode_FromString(string))
    except BaseException as e:
        context.exception = e
        return curl.CURL_FNMATCHFUNC_FAIL

cdef list slist_to_list(curl.curl_slist *head) with gil:
    """Converts curl slist to a python list."""
    cdef list result = []
    cdef curl.curl_slist *ptr = head
    while ptr:
        result.append(<bytes>(ptr.data))
        ptr = ptr.next
    curl.curl_slist_free_all(head)
    return result

@cython.final
@cython.no_gc
@cython.freelist(8)
cdef class WSFrame:
    cdef const curl.curl_ws_frame* frame
    @staticmethod
    cdef inline WSFrame from_ptr(const curl.curl_ws_frame* frame):
        cdef WSFrame self = WSFrame.__new__(WSFrame)
        self.frame = frame
        return self

    @property
    def age(self):
        return self.frame.age

    @property
    def flags(self):
        return self.frame.flags

    @property
    def offset(self):
        return self.frame.offset

    @property
    def bytesleft(self):
        return self.frame.bytesleft

    @property
    def len(self):
        return self.frame.len

@cython.final
@cython.no_gc
@cython.freelist(8)
cdef class Curl:
    """
    Wrapper for `curl_easy_*` functions of libcurl.
    """
    cdef:
        curl.CURL* _curl
        curl.curl_slist * _headers
        curl.curl_slist * _http3_headers
        curl.curl_slist * _ws_headers
        curl.curl_slist * _proxy_headers
        curl.curl_slist * _resolve
        str _cacert
        bint _is_cert_set
        public bint _skip_cacert
        object _write_handle
        object _header_handle
        object _debug_handle
        bytes _body_handle
        object _read_handle
        object _seek_handle
        object _trailer_handle
        object _prereq_handle
        object _xferinfo_handle
        object _fnmatch_handle
        char* _error_buffer # char[256]
        bint _debug

        size_t _WS_RECV_BUFFER_SIZE
        char* _ws_recv_buffer
        size_t _ws_recv_n_recv
        curl.curl_ws_frame* _ws_recv_p_frame
        size_t _ws_send_n_sent

    def __cinit__(self, str cacert = "", bint debug = False, object handle = None):
        """
        Parameters:
            cacert: CA cert path to use, by default, cycurl uses its own bundled cert.
            cacert: CA cert path to use, by default, cycurl uses certs from ``certifi``.
            debug: whether to show curl debug messages.
            handle: a curl handle in PyCapsule from ``curl_easy_init``.
        """
        # assert PyCapsule_CheckExact(handle)
        self._error_buffer = <char*>PyMem_Malloc(curl.CURL_ERROR_SIZE)
        if self._error_buffer == NULL:
            raise MemoryError
        if not handle:
            self._curl = curl.curl_easy_init()
            if self._curl == NULL:
                PyMem_Free(self._error_buffer)
                self._error_buffer = NULL
                raise MemoryError
        else:
            self._curl = <curl.CURL*>PyCapsule_GetPointer(handle, NULL)
        self._headers = NULL
        self._http3_headers = NULL
        self._ws_headers = NULL
        self._proxy_headers = NULL
        self._resolve = NULL
        self._cacert = cacert or DEFAULT_CACERT
        self._is_cert_set = False
        self._skip_cacert = False
        self._write_handle = None
        self._header_handle = None
        self._debug_handle = None
        self._body_handle = None
        self._read_handle = None
        self._seek_handle = None
        self._trailer_handle = None
        self._prereq_handle = None
        self._xferinfo_handle = None
        self._fnmatch_handle = None
        self._debug = debug
        self._set_error_buffer()

        # Pre-allocated C objects for WebSocket performance
        # self._ws_recv_buffer = ffi.new("char[]", self._WS_RECV_BUFFER_SIZE)
        # self._ws_recv_n_recv = ffi.new("size_t *")
        # self._ws_recv_p_frame = ffi.new("struct curl_ws_frame **")
        # self._ws_send_n_sent = ffi.new("size_t *")
        self._WS_RECV_BUFFER_SIZE = 128 * 1024  # 128 kB
        self._ws_recv_buffer = <char *> PyMem_Malloc(self._WS_RECV_BUFFER_SIZE)
        if self._ws_recv_buffer == NULL:
            raise MemoryError

    cdef inline void _close(self) noexcept nogil:
        # self.clean_handles_and_buffers() # we could add it here just like the cffi version, but it would require gil.
        if self._curl:
            curl.curl_easy_cleanup(self._curl)
            self._curl = NULL
        if self._resolve:
            curl.curl_slist_free_all(self._resolve)
            self._resolve = NULL
        if self._headers:
            curl.curl_slist_free_all(self._headers)
            self._headers = NULL
        if self._proxy_headers:
            curl.curl_slist_free_all(self._proxy_headers)
            self._proxy_headers = NULL

    def __dealloc__(self):
        if self._error_buffer:
            PyMem_Free(self._error_buffer)
            self._error_buffer = NULL
        if self._ws_recv_buffer:
            PyMem_Free(self._ws_recv_buffer)
            self._ws_recv_buffer = NULL
        self._close()

    def close(self):
        """Close and cleanup curl handle, wrapper for ``curl_easy_cleanup``."""
        self._close()

    cpdef inline tuple ws_recv(self):
        """Receive a frame from a websocket connection.
        Returns:
            a tuple of frame content and curl frame meta struct.
        Raises:
            CurlError: if failed.
        """
        if self._curl == NULL:
            raise CurlError("Cannot receive websocket data on closed handle.")
        
        # cdef char* buffer = <char*>PyMem_Malloc(n)
        # if buffer==NULL:
        #     raise MemoryError
        # cdef size_t n_recv
        cdef int ret
        # cdef const curl.curl_ws_frame* frame = NULL
        with nogil:
            ret = curl.curl_ws_recv(self._curl,
                                    self._ws_recv_buffer,
                                    self._WS_RECV_BUFFER_SIZE,
                                    &self._ws_recv_n_recv,
                                    &self._ws_recv_p_frame)
        if ret:
            self._check_error(ret, "WS_RECV")
        # Frame meta explained: https://curl.se/libcurl/c/curl_ws_meta.html
        # return <bytes>buffer[: n_recv], WSFrame.from_ptr(frame)
        return <bytes>self._ws_recv_buffer[:self._ws_recv_n_recv], WSFrame.from_ptr(self._ws_recv_p_frame)

    cpdef inline size_t ws_send(self, const uint8_t[::1] payload, unsigned int flags = curl.CURLWS_BINARY):
        """Send data to a websocket connection.
        Args:
            payload: content to send.
            flags: websocket flag to set for the frame, default: binary.
        Returns:
            The number of bytes sent.
        Raises:
            CurlError: if failed.
        """
        if self._curl == NULL:
            raise CurlError("Cannot send websocket data on closed handle.")
        
        # cdef size_t n_sent
        cdef int ret
        # n_sent = ffi.new("int *")
        # buffer = ffi.from_buffer(payload)
        with nogil:
            ret = curl.curl_ws_send(self._curl, <const void *>&payload[0], <size_t>payload.shape[0], &self._ws_send_n_sent, 0, flags)
        if ret:
            self._check_error(ret, "WS_SEND")
        return self._ws_send_n_sent

    def ws_close(self, int code = 1000, bytes message = b""):
        """Close a websocket connection. Shorthand for :meth:`ws_send`
        with close code and message. Note that to completely close the connection,
        you must close the curl handle after this call with :meth:`close`.
        Args:
            code: close code.
            message: close message.
        Returns:
            0 if no error.
        Raises:
            CurlError: if failed.
        """
        payload = struct.pack("!H", code) + message
        return self.ws_send(payload, flags=CURLWS_CLOSE)

    def ws_meta(self):
        cdef const curl.curl_ws_frame* frame = curl.curl_ws_meta(self._curl)
        return WSFrame.from_ptr(frame)

    cdef inline void _set_error_buffer(self) nogil:
        cdef int ret = curl._curl_easy_setopt(self._curl, curl.CURLOPT_ERRORBUFFER, self._error_buffer)
        if ret != 0:
            with gil:
                warnings.warn("Failed to set error buffer", CurlWarning, stacklevel=2)
        if self._debug:
            with gil:
                self.debug()

    def __eq__(self, other):
        if not isinstance(other, Curl):
            return False
        return self._curl == (<Curl>other)._curl

    def __hash__(self):
        return <Py_hash_t>(self._curl)

    def debug(self):
        """Set debug to True"""
        self.setopt(curl.CURLOPT_VERBOSE, 1)
        self.setopt(curl.CURLOPT_DEBUGFUNCTION, True)

    cdef int _check_error(self, int errcode, str args) except -1:
        if errcode == 0:
            return 0
        error = self._get_error(errcode, args)
        if error is not None:
            raise error

    cdef _get_error(self, int errcode, str args):
        if errcode != 0:
            errmsg = (<bytes>self._error_buffer).decode(errors="backslashreplace")
            return CurlError(
                f"Failed to {args}, curl: ({errcode}) {errmsg}. "
                "See https://curl.se/libcurl/c/libcurl-errors.html first for more details.",
                code=errcode,
            )

    cpdef object _get_callback_exception(self):
        cdef object handle
        handle = self._write_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._header_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._debug_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._read_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._seek_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._trailer_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._prereq_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._xferinfo_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        handle = self._fnmatch_handle
        if handle is not None:
            exception = <_CallbackContext>handle.exception
            if exception is not None:
                return exception

        return None

    cpdef inline int setopt(self, int option, object value) except -1:
        """Wrapper for ``curl_easy_setopt``.
    
        Args:
            option: option to set, using constants from CURLOPT_
            value: value to set, strings will be handled automatically

        Returns:
            0 if no error, see ``CURLE_``.
        """
        # input_option = {
        #     # this should be int in curl, but cffi requires pointer for void*
        #     # it will be convert back in the glue c code.
        #     0: "int*",
        #     10000: "char*",
        #     20000: "void*",
        #     30000: "int*",  # offset type
        # }
        # print("option", option, "value", value)

        if self._curl == NULL:
            return 0
        cdef:
            void* c_value = NULL
            int value_type = option / 10000 * 10000  # "cdivision": True
            int64_t intval
            bytes bytesval
            int ret
        if value_type == 30000 or value_type == 0:
            # c_value = ffi.new("long*", value)
            intval = <int64_t>value
            c_value = <void*>&intval
        elif option == curl.CURLOPT_WRITEDATA:
            self._write_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._write_handle
            curl._curl_easy_setopt(
                self._curl, curl.CURLOPT_WRITEFUNCTION, <void*>buffer_callback
            )
        elif option == curl.CURLOPT_HEADERDATA:
            self._header_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._header_handle
            curl._curl_easy_setopt(
                self._curl, curl.CURLOPT_HEADERFUNCTION, <void*>buffer_callback
            )
        elif option == curl.CURLOPT_READDATA:
            self._read_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._read_handle
            curl._curl_easy_setopt(
                self._curl, curl.CURLOPT_READFUNCTION, <void*>read_buffer_callback
            )
        elif option == curl.CURLOPT_WRITEFUNCTION:
            self._write_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._write_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_WRITEFUNCTION, <void*>write_callback)
            option = curl.CURLOPT_WRITEDATA
        elif option == curl.CURLOPT_HEADERFUNCTION:
            self._header_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._header_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_HEADERFUNCTION, <void*>write_callback)
            option = curl.CURLOPT_HEADERDATA
        elif option == curl.CURLOPT_DEBUGFUNCTION:
            if value is True:
                value = debug_function_default
            self._debug_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._debug_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_DEBUGFUNCTION, <void*>debug_function)
            option = curl.CURLOPT_DEBUGDATA
        elif option == curl.CURLOPT_READFUNCTION:
            self._read_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._read_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_READFUNCTION, <void*>read_callback)
            option = curl.CURLOPT_READDATA
        elif option == curl.CURLOPT_SEEKDATA:
            self._seek_handle = _CallbackContext(value) # store a ref of this stream
            c_value = <void*>self._seek_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_SEEKFUNCTION, <void*>seek_buffer_callback)
        elif option == curl.CURLOPT_SEEKFUNCTION:
            self._seek_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._seek_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_SEEKFUNCTION, <void*>seek_callback)
            option = curl.CURLOPT_SEEKDATA
        elif option == curl.CURLOPT_TRAILERFUNCTION:
            self._trailer_handle = _CallbackContext(value) # store a ref
            c_value = <void*>self._trailer_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_TRAILERFUNCTION, <void*>trailer_callback)
            option = curl.CURLOPT_TRAILERDATA
        elif option == curl.CURLOPT_PREREQFUNCTION:
            self._prereq_handle = _CallbackContext(value)
            c_value = <void *> self._prereq_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_PREREQFUNCTION, <void *> prereq_callback)
            option = curl.CURLOPT_PREREQDATA
        elif option == curl.CURLOPT_XFERINFOFUNCTION:
            self._xferinfo_handle = _CallbackContext(value)
            c_value = <void *> self._xferinfo_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_XFERINFOFUNCTION, <void *> xferinfo_callback)
            option = curl.CURLOPT_XFERINFODATA
        elif option == curl.CURLOPT_FNMATCH_FUNCTION:
            self._fnmatch_handle = _CallbackContext(value)
            c_value = <void *> self._fnmatch_handle
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_FNMATCH_FUNCTION, <void *> fnmatch_callback)
            option = curl.CURLOPT_FNMATCH_DATA
        elif value_type == 10000:
            if isinstance(value, str):
                # Windows/libcurl expects ANSI code page for file paths (char*).
                # Non-ASCII paths encoded as UTF-8 can trigger ErrCode 77.
                # Encode file-path-like options using the system encoding on Windows.
                filepath_opts = {
                    CURLOPT_CAINFO,
                    CURLOPT_CAPATH,
                    CURLOPT_PROXY_CAINFO,
                    CURLOPT_PROXY_CAPATH,
                    CURLOPT_SSLCERT,
                    CURLOPT_SSLKEY,
                    CURLOPT_CRLFILE,
                    CURLOPT_ISSUERCERT,
                    CURLOPT_SSH_PUBLIC_KEYFILE,
                    CURLOPT_SSH_PRIVATE_KEYFILE,
                    CURLOPT_COOKIEFILE,
                    CURLOPT_COOKIEJAR,
                    CURLOPT_NETRC_FILE,
                    CURLOPT_UNIX_SOCKET_PATH,
                }
                if sys.platform.startswith("win") and option in filepath_opts:
                    # Use the process ANSI code page to match what CRT fopen expects.
                    enc = locale.getpreferredencoding(False)
                    bytesval = value.encode(enc, errors="strict")
                else:
                    bytesval = value.encode()
                c_value = <void *> <const char *> bytesval
                # c_value = <void*>PyUnicode_AsUTF8AndSize(value, NULL)
            elif isinstance(value, bytes):
                bytesval = value
                # c_value = <void*><const char*>value
                c_value = <void*><const char *> bytesval
            elif PyCapsule_CheckExact(value):
                c_value = PyCapsule_GetPointer(value, NULL)
            # Must keep a reference, otherwise may be GCed.
            if option == curl.CURLOPT_POSTFIELDS:
                self._body_handle = bytesval
        else:
            raise NotImplementedError("Option unsupported: %s" % option)

        if option == curl.CURLOPT_HTTPHEADER:
            for header in value:
                self._headers = curl.curl_slist_append(self._headers, <const char*>header)
            ret = curl._curl_easy_setopt(self._curl, option, self._headers)
        elif option == curl.CURLOPT_HTTP3_HTTPHEADER:
            for header in value:
                self._http3_headers = curl.curl_slist_append(self._http3_headers, <const char*>header)
            ret = curl._curl_easy_setopt(self._curl, option, self._http3_headers)
        elif option == curl.CURLOPT_WS_HTTPHEADER:
            for header in value:
                self._ws_headers = curl.curl_slist_append(self._ws_headers, <const char*>header)
            ret = curl._curl_easy_setopt(self._curl, option, self._ws_headers)
        elif option == curl.CURLOPT_PROXYHEADER:
            for proxy_header in value:
                self._proxy_headers = curl.curl_slist_append(self._proxy_headers, <const char*>proxy_header)
            ret = curl._curl_easy_setopt(self._curl, option, self._proxy_headers)
        elif option == curl.CURLOPT_RESOLVE:
            for resolve in value:
                if isinstance(resolve, str):
                    resolve = resolve.encode()
                self._resolve = curl.curl_slist_append(self._resolve, resolve)
            ret = curl._curl_easy_setopt(self._curl, option, self._resolve)
        else:
            ret = curl._curl_easy_setopt(self._curl, option, c_value)
        self._check_error(ret, f"setopt {option} {value}")

        if option == curl.CURLOPT_CAINFO:
            self._is_cert_set = True

        return ret

    cpdef inline object getinfo(self, int option):
        """Wrapper for ``curl_easy_getinfo``. Gets information in response after curl perform.
        Parameters:
            option: option to get info of, use the constants from CURLINFO_
            option: option to get info of, using constants from ``CURLINFO_`` constants
        Returns:
            value retrieved from last perform.
        """
        # ret_option = {
        #     0x100000: "char**",
        #     0x200000: "long*",
        #     0x300000: "double*",
        #     0x400000: "struct curl_slist **",
        #     0x500000: "uintptr_t*",
        #     0x600000: "int64_t*"
        # }
        # ret_cast_option = {
        #     0x100000: ffi.string,
        #     0x200000: int,
        #     0x300000: float,
        #     0x500000: int,
        #     0x600000: int
        # }
        cdef:
            int ret_type
            int ret=0
            char* charret = NULL
            long longret=0
            uintptr_t uintptrret=0
            double doubleret=0.0
            curl.curl_slist *slistret = NULL
            int64_t int64ret
        ret_type = option & 0xF00000
        if self._curl == NULL:
            if ret_type == 0x100000:
                return b""
            elif ret_type == 0x200000 or ret_type == 0x500000 or ret_type == 0x600000:
                return 0
            elif ret_type == 0x300000:
                return 0.0
            elif ret_type == 0x400000:
                return []
        # c_value = ffi.new(ret_option[option & 0xF00000])
        if ret_type == 0x100000:
            ret = curl.curl_easy_getinfo(self._curl, option, &charret)
            self._check_error(ret, f"getinfo {option}")
            if charret == NULL:
                return b""
            return <bytes>charret
        elif ret_type == 0x200000:
            ret = curl.curl_easy_getinfo(self._curl, option, &longret)
            self._check_error(ret, f"getinfo {option}")
            return PyLong_FromLong(longret)
        elif ret_type == 0x300000:
            ret = curl.curl_easy_getinfo(self._curl, option, &doubleret)
            self._check_error(ret, f"getinfo {option}")
            return PyFloat_FromDouble(doubleret)
        elif ret_type == 0x400000:
            ret = curl.curl_easy_getinfo(self._curl, option, &slistret)
            self._check_error(ret, f"getinfo {option}")
            if slistret == NULL:
                return []
            return slist_to_list(slistret)
        elif ret_type == 0x500000:
            ret = curl._curl_easy_getinfo_socket(self._curl, option, &uintptrret)
            self._check_error(ret, f"getinfo {option}")
            if <int>uintptrret == curl.CURL_SOCKET_BAD:
                return PyLong_FromLong(-1)
            return PyLong_FromLong(uintptrret)
        elif ret_type == 0x600000:
            ret = curl.curl_easy_getinfo(self._curl, option, &int64ret)
            self._check_error(ret, f"getinfo {option}")
            return int64ret

    cpdef inline bytes version(self):
        """Get the underlying libcurl version."""
        return <bytes>curl.curl_version()

    cpdef inline int impersonate(self, target: str, bint default_headers = True):
        """Set the browser type to impersonate.
    
        Parameters:
            target: browser to impersonate.
            default_headers: whether to add default headers, like User-Agent.
        
        Returns:
            0 if no error.
        """
        if self._curl == NULL:
            return 0
        cdef bytes data = target.encode()
        return curl.curl_easy_impersonate(self._curl, <const char *>data, default_headers)

    cdef inline int _ensure_cacert(self) except -1:
        if self._skip_cacert:
            return 0
        if not self._is_cert_set:
            ret = self.setopt(curl.CURLOPT_CAINFO, self._cacert)
            self._check_error(ret, "set cacert")
            ret = self.setopt(curl.CURLOPT_PROXY_CAINFO, self._cacert)
            self._check_error(ret, "set proxy cacert")

    cpdef inline int perform(self, bint clear_headers = True, bint clear_resolve = True) except -1:
        """Wrapper for ``curl_easy_perform``, performs a curl request.

        Parameters:
            clear_headers: clear header slist used in this perform
            clear_resolve: clear resolve slist used in this perform
        
        Raises:
            CurlError: if the perform was not successful.
        """
        if self._curl == NULL:
            raise CurlError("Cannot perform request on closed handle.")
        cdef int ret
        # make sure we set a cacert store
        self._ensure_cacert()

        # here we go
        with nogil:
            ret = curl.curl_easy_perform(self._curl)
        try:
            callback_exception = self._get_callback_exception()
            if callback_exception is not None:
                raise callback_exception
            self._check_error(ret, "perform")
            return ret
        finally:
            # cleaning
            self.clean_handles_and_buffers(clear_headers, clear_resolve)

    cpdef inline int upkeep(self):
        if self._curl == NULL:
            return 0
        cdef int ret
        with nogil:
            ret = curl.curl_easy_upkeep(self._curl)
        return ret

    cpdef int pause(self, int action) except -1:
        """Pause or resume data transfer on this handle."""
        if self._curl == NULL:
            return 0
        cdef int ret
        with nogil:
            ret = curl.curl_easy_pause(self._curl, action)
        self._check_error(ret, "pause")
        return ret

    cpdef inline clean_handles_and_buffers(self, bint clear_headers = True, bint clear_resolve = True):
        """Clean up handles and buffers after ``perform`` and ``close``,
        called at the end of ``perform`` and ``close``."""
        self._write_handle = None
        self._header_handle = None
        self._debug_handle = None
        self._body_handle = None
        self._read_handle = None
        self._seek_handle = None
        self._trailer_handle = None
        self._prereq_handle = None
        self._xferinfo_handle = None
        self._fnmatch_handle = None
        if clear_resolve:
            if self._resolve != NULL:
                curl.curl_slist_free_all(self._resolve)
                self._resolve = NULL
        if clear_headers:
            if self._headers != NULL:
                curl.curl_slist_free_all(self._headers)
                self._headers = NULL

            if self._http3_headers != NULL:
                curl.curl_slist_free_all(self._http3_headers)
                self._http3_headers = NULL

            if self._ws_headers != NULL:
                curl.curl_slist_free_all(self._ws_headers)
                self._ws_headers = NULL

            if self._proxy_headers != NULL:
                curl.curl_slist_free_all(self._proxy_headers)
                self._proxy_headers = NULL


    cpdef inline Curl duphandle(self):
        """Wrapper for ``curl_easy_duphandle``.
        This is not a full copy of entire curl object in python. For example, headers
        handle is not copied, you have to set them again."""
        if self._curl == NULL:
            raise CurlError("Cannot duplicate closed handle.")
        cdef curl.CURL *new_handle
        with nogil:
            new_handle = curl.curl_easy_duphandle(self._curl)
        if new_handle == NULL:
            raise MemoryError
        c = Curl(self._cacert, self._debug, PyCapsule_New(<void*>new_handle, NULL, NULL))
        return c

    def reset(self):
        """Reset all curl options, wrapper for ``curl_easy_reset``."""
        self._is_cert_set = False
        self._skip_cacert = False
        if self._curl:
            with nogil:
                curl.curl_easy_reset(self._curl)
            self._set_error_buffer()
        if self._resolve != NULL:
            curl.curl_slist_free_all(self._resolve)
            self._resolve = NULL

    def parse_cookie_headers(self, list headers) -> SimpleCookie:
        """Extract ``cookies.SimpleCookie`` from header lines.

        Parameters:
            headers: list of headers in bytes.

        Returns:
            A parsed cookies.SimpleCookie instance.
        """
        cookie = SimpleCookie()
        for header in headers:
            if header.lower().startswith(b"set-cookie: "):
                cookie.load(header[12:].decode())  # len("set-cookie: ") == 12
        return cookie

    @staticmethod
    def get_reason_phrase(bytes status_line) -> bytes:
        """Extract reason phrase, like ``OK``, ``Not Found`` from response status line."""
        m = REASON_PHRASE_RE.match(status_line)
        return m.group(1) if m else b""

    @staticmethod
    def parse_status_line(bytes status_line) -> tuple:
        """Parse status line.
        Returns:
            http_version, status_code, and reason phrase
        """
        m = STATUS_LINE_RE.match(status_line)
        if not m:
            return CURL_HTTP_VERSION_1_0, 0, b""
        if m.group(1) == "2.0":
            http_version = CURL_HTTP_VERSION_2_0
        elif m.group(1) == "1.1":
            http_version = CURL_HTTP_VERSION_1_1
        elif m.group(1) == "1.0":
            http_version = CURL_HTTP_VERSION_1_0
        else:
            http_version = CURL_HTTP_VERSION_NONE
        status_code = int(m.group(2))
        reason = m.group(3)

        return http_version, status_code, reason

### The asyncio ###

include "_asyncio_selector.pxi"
if sys.platform == "win32":
    # registry of asyncio loop : selector thread
    _selectors: WeakKeyDictionary = WeakKeyDictionary()
    PROACTOR_WARNING = """
    Proactor event loop does not implement add_reader family of methods required.
    Registering an additional selector thread for add_reader support.
    To avoid this warning use:
        asyncio.set_event_loop_policy(WindowsSelectorEventLoopPolicy())
    """

    def get_selector(asyncio_loop: asyncio.AbstractEventLoop) -> asyncio.AbstractEventLoop:
        """Get selector-compatible loop

        Returns an object with ``add_reader`` family of methods,
        either the loop itself or a SelectorThread instance.

        Workaround Windows proactor removal of *reader methods.
        """

        if asyncio_loop in _selectors:
            return _selectors[asyncio_loop]

        if not isinstance(asyncio_loop, getattr(asyncio, "ProactorEventLoop", type(None))):
            return asyncio_loop

        warnings.warn(PROACTOR_WARNING, CurlWarning, stacklevel=2)

        selector_loop = _selectors[asyncio_loop] = AddThreadSelectorEventLoop(asyncio_loop)  # type: ignore

        # patch loop.close to also close the selector thread
        loop_close = asyncio_loop.close

        def _close_selector_and_loop():
            # restore original before calling selector.close,
            # which in turn calls eventloop.close!
            asyncio_loop.close = loop_close
            _selectors.pop(asyncio_loop, None)
            selector_loop.close()

        asyncio_loop.close = _close_selector_and_loop  # type: ignore # mypy bug - assign a function to method
        return selector_loop

else:
    def get_selector(loop: asyncio.AbstractEventLoop) -> asyncio.AbstractEventLoop:
        return loop


cdef int timer_function(curl.CURLM *curlm, long timeout_ms, void *clientp) with gil:
    """
    see: https://curl.se/libcurl/c/CURLMOPT_TIMERFUNCTION.html
    """
    cdef AsyncCurl async_curl = <AsyncCurl>clientp
    # Cancel the timer anyway, if it's -1, yes, libcurl says it should be cancelled.
    # If not, to add a new timer, we need to cancel the old timer.
    if async_curl._timer:
        async_curl._timer.cancel()  # If already called, cancel does nothing.
        async_curl._timer = None

    # libcurl says to install a timer which calls socket_action on fire.
    async_curl._timer = async_curl.loop.call_later(
        (<double>timeout_ms) / 1000,
        async_curl.process_data,
        curl.CURL_SOCKET_TIMEOUT,  # -1
        curl.CURL_POLL_NONE,  # 0
    )
    return 0

cdef int socket_function(curl.CURL *curl_, int sockfd, int what, void *clientp, void *socketp) with gil:
    """This callback is called when libcurl decides it's time to interact with certain
    sockets"""
    cdef AsyncCurl async_curl = <AsyncCurl>clientp
    cdef object loop = async_curl.loop

    # Always remove and re-add fds
    if sockfd in async_curl._sockfds:
        loop.remove_reader(sockfd)
        loop.remove_writer(sockfd)
    # Need to read from the socket
    if what & curl.CURL_POLL_IN:
        loop.add_reader(sockfd, async_curl.process_data, sockfd, curl.CURL_CSELECT_IN)
        async_curl._sockfds.add(sockfd)
    # Need to write to the socket
    if what & curl.CURL_POLL_OUT:
        loop.add_writer(sockfd, async_curl.process_data, sockfd, curl.CURL_CSELECT_OUT)
        async_curl._sockfds.add(sockfd)
    # Need to remove the socket
    if what & curl.CURL_POLL_REMOVE:
        async_curl._sockfds.remove(sockfd)
    return 0

# """
# libcurl provides an event-based system for multiple handles with the following API:
# - curl_multi_socket_action, for detecting events
# - curl_multi_info_read, for reading the transfer status
# There are 2 callbacks:
# - socket_function, set by CURLMOPT_SOCKETFUNCTION, will be called for socket events.
# - timer_function, set by CURLMOPT_TIMERFUNCTION, will be called when timeouts happen.
# And it works like the following:
# Set up handles, callbacks first.
# When started, curl_multi_socket_action should be called to start everything.
# If there are data in/out, libcurl calls the socket_function callback, and it sets up
# `process_data` as asyncio loop reader/writer function. `process_data` will call
# curl_multi_info_read to determine whether a certain `await perform` has finished.
# When idle, libcurl will call the timer_function callback, which sets up a later call
# for socket_action to detect events.
# """

@cython.final
@cython.no_gc
cdef class AsyncCurl:
    cdef:
        curl.CURLM *_curlm
        public str _cacert # session.py L1126 wants to access this,
        dict _curl2future  # Dict[Curl, asyncio.Future]
        dict _curl2curl  #  c curl to Curl
        set _sockfds   # sockfds
        object loop
        object _timeout_checker  # asyncio.Task
        object _timer   # Optional[asyncio.TimerHandle]

    def __cinit__(self, str cacert = "", object loop=None):
        self._curlm = curl.curl_multi_init()
        if self._curlm == NULL:
            raise MemoryError
        self._cacert = cacert or DEFAULT_CACERT
        self._curl2future = {}  # curl to future map
        self._curl2curl = {}  # c curl to Curl Dict[int, Curl]
        self._sockfds = set()  # sockfds
        self.loop = get_selector(
            loop if loop is not None else asyncio.get_running_loop()
        )
        self._timeout_checker = self.loop.create_task(self._force_timeout())
        self._timer: Optional[asyncio.TimerHandle] = None
        self._setup()

    def __dealloc__(self):
        if self._curlm:
            curl.curl_multi_cleanup(self._curlm)
            self._curlm = NULL

    cdef _setup(self):
        curl.curl_multi_setopt(self._curlm, curl.CURLMOPT_TIMERFUNCTION, <void *>timer_function)
        curl.curl_multi_setopt(self._curlm, curl.CURLMOPT_SOCKETFUNCTION, <void *>socket_function)
        curl.curl_multi_setopt(self._curlm, curl.CURLMOPT_SOCKETDATA, <void*>self)
        curl.curl_multi_setopt(self._curlm, curl.CURLMOPT_TIMERDATA, <void*>self)
        # curl.curl_multi_setopt(self._curlm, curl.CURLMOPT_PIPELINING, curl.CURLPIPE_NOTHING)

    async def close(self):
        """Close and cleanup running timers, readers, writers and handles."""
        # Close and wait for the force timeout checker to complete
        self._timeout_checker.cancel()
        with suppress(asyncio.CancelledError):
            await self._timeout_checker
        # Close all pending futures
        for curl_, future in self._curl2future.items():
            curl.curl_multi_remove_handle(self._curlm, (<Curl>curl_)._curl)
            if not future.done() and not future.cancelled():
                future.set_result(None)
        # Cleanup curl_multi handle
        curl.curl_multi_cleanup(self._curlm)
        self._curlm = NULL
        # Remove add readers and writers
        for sockfd in self._sockfds:
            self.loop.remove_reader(sockfd)
            self.loop.remove_writer(sockfd)
        # Cancel all time functions
        if self._timer:
            self._timer.cancel()

    async def _force_timeout(self):
        """This coroutine is used to safeguard from any missing signals from curl, and
        put everything back on track"""
        while True:
            if not self._curlm:
                break
            self.socket_action(curl.CURL_SOCKET_TIMEOUT, curl.CURL_POLL_NONE)
            await asyncio.sleep(0.1)

    cpdef inline add_handle(self, Curl curl_):
        """Add a curl handle to be managed by curl_multi. This is the equivalent of
        `perform` in the async world."""

        curl_._ensure_cacert()
        cdef int errcode
        with nogil:
            errcode = curl.curl_multi_add_handle(self._curlm, curl_._curl)
        self._check_error(errcode)
        future = self.loop.create_future()
        self._curl2future[curl_] = future
        self._curl2curl[<long long><void*>curl_._curl] = curl_
        return future

    cpdef inline int socket_action(self, int sockfd, int ev_bitmask) except -1:
        """wrapper for curl_multi_socket_action, 
        returns the number of running curl handles."""
        cdef int running_handle
        cdef int errcode
        with nogil:
            errcode = curl.curl_multi_socket_action(self._curlm, sockfd, ev_bitmask, &running_handle)
        self._check_error(errcode)
        return running_handle

    cpdef inline process_data(self, int sockfd, int ev_bitmask):
        """Call curl_multi_info_read to read data for given socket."""
        if not self._curlm:
            warnings.warn(
                "Curlm already closed! quitting from process_data", CurlWarning, stacklevel=2
            )
            return

        self.socket_action(sockfd, ev_bitmask)

        cdef:
            int msg_in_queue
            int retcode
            curl.CURLMsg *curl_msg
            Curl curl_
        while True:
            try:
                curl_msg = curl.curl_multi_info_read(self._curlm, &msg_in_queue)
                # NULL is returned as a signal that no more to be get at this point
                if curl_msg == NULL:
                    break
                if curl_msg.msg == curl.CURLMSG_DONE:
                    curl_ = <Curl>self._curl2curl[<long long><void*>curl_msg.easy_handle]
                    retcode = curl_msg.data.result
                    callback_exception = curl_._get_callback_exception()
                    if callback_exception is not None:
                        self.set_exception(curl_, callback_exception)
                    elif retcode == 0:
                        self.set_result(curl_)
                    else:
                        self.set_exception(curl_, curl_._get_error(retcode, "perform"))
                else:
                    print("NOT DONE")  # Will not reach, for nothing else being defined.
            except Exception:
                warnings.warn(
                    "Unexpected curl multi state in process_data, "
                    "please open an issue on GitHub\n",
                    CurlWarning,
                    stacklevel=2,
                )

    cdef inline object _pop_future(self, Curl curl_):
        cdef int errcode
        with nogil:
            errcode = curl.curl_multi_remove_handle(self._curlm, curl_._curl)
        self._check_error(errcode)
        self._curl2curl.pop(<long long><void*>curl_._curl, None)
        return self._curl2future.pop(curl_, None)

    cpdef inline object remove_handle(self, Curl curl_):
        """Cancel a future for given curl handle."""
        cdef object future = self._pop_future(curl_)
        if future and not future.done() and not future.cancelled():
            future.cancel()

    cdef inline object set_result(self, Curl curl_):
        """Mark a future as done for given curl handle."""
        cdef object future = self._pop_future(curl_)
        if future and not future.done() and not future.cancelled():
            future.set_result(None)

    cdef inline set_exception(self, Curl curl_, object exception):
        """Raise exception of a future for given curl handle."""
        cdef object future = self._pop_future(curl_)
        if future and not future.done() and not future.cancelled():
            future.set_exception(exception)

    def _check_error(self, int errcode, *args):
        if errcode == curl.CURLE_OK:
            return
        cdef const char *errmsg = curl.curl_multi_strerror(errcode)
        cdef str action = " ".join([str(a) for a in args])
        raise CurlError(
            f"Failed in {action}, multi: ({errcode}) {PyUnicode_FromString(errmsg)}. "
            "See https://curl.se/libcurl/c/libcurl-errors.html first for more "
            "details. Please open an issue on GitHub to help debug this error.",
        )

@cython.freelist(8)
@cython.no_gc
@cython.final
cdef class CurlMime:
    """Wrapper for the ``curl_mime_`` API."""

    cdef:
        Curl _curl
        curl.curl_mime *form

    def __init__(self, Curl curl_ = None):
        """
        Args:
            curl: Curl instance to use.
        """
        self._curl = curl_ if curl_ else Curl()
        self.form = curl.curl_mime_init(self._curl._curl)

    @property
    def _form(self):
        return PyCapsule_New(self.form, NULL, NULL)

    cpdef inline addpart(
        self,
        str name,
        str content_type = None,
        str filename = None,
        object local_path = None,  # Optional[Union[str, bytes, Path]]
        object data = None,
    ):
        """Add a mime part for a mutlipart html form.
        Note: You can only use either local_path or data, not both.
        Args:
            name: name of the field.
            content_type: content_type for the field. for example: ``image/png``.
            filename: filename for the server.
            local_path: file to upload on local disk.
            data: file content to upload.
        """
        cdef curl.curl_mimepart *part = curl.curl_mime_addpart(self.form)
        cdef int ret
        cdef bytes bytesname = name.encode()
        ret = curl.curl_mime_name(part, <const char *>bytesname)
        if ret != 0:
            raise CurlError("Add field failed.")

        # mime type
        cdef bytes bytescontent_type
        if content_type is not None:
            bytescontent_type = content_type.encode()
            ret = curl.curl_mime_type(part, <const char *>bytescontent_type)
            if ret != 0:
                raise CurlError("Add field failed.")

        if local_path is not None and data is not None:
            raise CurlError("Can not use local_path and data at the same time.")

        # this is a filename
        if local_path is not None:
            if isinstance(local_path, Path):
                local_path_str = str(local_path)
            elif isinstance(local_path, bytes):
                local_path_str = local_path.decode()
            else:
                local_path_str = local_path

            if not Path(local_path_str).exists():
                raise FileNotFoundError(f"File not found at {local_path_str}")
            ret = curl.curl_mime_filedata(part, PyUnicode_AsUTF8(local_path_str))
            if ret != 0:
                raise CurlError("Add field failed.")

        # remote file name
        if filename is not None:
            ret = curl.curl_mime_filename(part, PyUnicode_AsUTF8(filename))
            if ret != 0:
                raise CurlError("Add field failed.")

        if data is not None:
            if not isinstance(data, bytes):
                data = str(data).encode()
            ret = curl.curl_mime_data(part, <const char *>data, PyBytes_GET_SIZE(data))
            if ret != 0:
                raise CurlError("Add data failed.")

    @classmethod
    def from_list(cls, list files):  # files: List[dict]
        """Create a multipart instance from a list of dict, for keys, see ``addpart``"""
        cdef CurlMime form = cls()
        for file in files:
            form.addpart(**file)
        return form

    cpdef inline attach(self, Curl curl_ = None):
        """Attach the mime instance to a curl instance."""
        cdef Curl c = curl_ if curl_ is not None else self._curl
        c.setopt(curl.CURLOPT_MIMEPOST, PyCapsule_New(self.form, NULL, NULL))

    cpdef inline close(self):
        """Close the mime instance and underlying files. This method must be called after
        ``perform`` or ``request``."""
        curl.curl_mime_free(self.form)
        self.form = NULL

    def __dealloc__(self):
        self.close()

cpdef inline bytes version():
    """Get the underlying libcurl version."""
    return <bytes>curl.curl_version()