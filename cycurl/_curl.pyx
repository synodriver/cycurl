# cython: language_level=3
# cython: cdivision=True
cimport cython
from cpython.float cimport PyFloat_FromDouble
from cpython.long cimport PyLong_FromLong
from cpython.mem cimport PyMem_Free, PyMem_Malloc
from cpython.pycapsule cimport PyCapsule_CheckExact, PyCapsule_GetPointer, PyCapsule_New
from libc.stdio cimport fflush, fprintf, fwrite, stderr

include "consts.pxi"

import asyncio
import re
import sys
import warnings
from enum import IntEnum
from http.cookies import SimpleCookie
from weakref import WeakKeyDictionary, WeakSet

import certifi

DEFAULT_CACERT = certifi.where()


class CurlHttpVersion(IntEnum):
    NONE = 0
    V1_0 = 1  # please use HTTP 1.0 in the request */
    V1_1 = 2  # please use HTTP 1.1 in the request */
    V2_0 = 3  # please use HTTP 2 in the request */
    V2TLS = 4  # use version 2 for HTTPS, version 1.1 for HTTP */
    V2_PRIOR_KNOWLEDGE = 5  # please use HTTP 2 without HTTP/1.1 Upgrade */
    V3 = 30  # Makes use of explicit HTTP/3 without fallback.


class CurlError(Exception):
    """Base exception for cycurl package"""

    def __init__(self, msg, code: int = 0, *args, **kwargs):
        super().__init__(msg, *args, **kwargs)
        self.code = code


cdef int debug_function(curl.CURL *curl_, int type_, char *data, size_t size, void *clientp) nogil:
    if type_ == curl.CURLINFO_SSL_DATA_IN or type_ == curl.CURLINFO_SSL_DATA_OUT:
        fprintf(stderr, "SSL OUT:")
        fwrite(data, sizeof(char), size, stderr)
        fprintf(stderr, "\n")
    elif type_ == curl.CURLINFO_DATA_IN or type_ == curl.CURLINFO_DATA_OUT:
        fprintf(stderr, "DATA OUT:")
        fwrite(data, sizeof(char), size, stderr)
        fprintf(stderr, "\n")
    else:
        fwrite(data, sizeof(char), size, stderr)
    fflush(stderr)
    return 0


cdef size_t buffer_callback(char *ptr, size_t size, size_t nmemb, void *userdata) with gil:
    cdef size_t total = size*nmemb
    cdef object stream
    stream = <object>userdata
    stream.write(<bytes>ptr[:total])
    return total

cdef size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) with gil:
    cdef:
        size_t total
        object callback
        size_t wrote
    total = size*nmemb
    callback = <object>userdata
    wrote = callback(<bytes>ptr[:total])
    if <unsigned int>wrote == curl.CURL_WRITEFUNC_PAUSE or <unsigned int>wrote == curl.CURL_WRITEFUNC_ERROR:
        return wrote
    # should make this an exception in future versions
    if wrote != total:
        warnings.warn("Wrote bytes != received bytes.", RuntimeWarning)
    return total

cdef list slist_to_list(curl.curl_slist *head) with gil:
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
cdef class Curl:
    """
    Wrapper for `curl_easy_*` functions of libcurl.
    """
    cdef:
        curl.CURL* _curl
        curl.curl_slist * _headers
        curl.curl_slist * _resolve
        str _cacert
        bint _is_cert_set
        object _write_handle
        object _header_handle
        bytes _body_handle
        char* _error_buffer # char[256]
        bint _debug

    def __cinit__(self, str cacert = DEFAULT_CACERT, bint debug = False, object handle = None):
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
        self._resolve = NULL
        self._cacert = cacert
        self._is_cert_set = False
        self._write_handle = None
        self._header_handle = None
        self._body_handle = None
        self._debug = debug
        self._set_error_buffer()

    cdef inline void _close(self) noexcept nogil:
        if self._curl:
            curl.curl_easy_cleanup(self._curl)
            self._curl = NULL
        if self._resolve:
            curl.curl_slist_free_all(self._resolve)
            self._resolve = NULL
        if self._headers:
            curl.curl_slist_free_all(self._headers)
            self._headers = NULL

    def __dealloc__(self):
        if self._error_buffer:
            PyMem_Free(self._error_buffer)
            self._error_buffer = NULL
        self._close()

    def close(self):
        """Close and cleanup curl handle, wrapper for curl_easy_cleanup"""
        self._close()

    cdef inline void _set_error_buffer(self) nogil:
        cdef int ret = curl._curl_easy_setopt(self._curl, curl.CURLOPT_ERRORBUFFER, self._error_buffer)
        if ret != 0:
            with gil:
                warnings.warn("Failed to set error buffer")
        if self._debug:
            with gil:
                self.setopt(curl.CURLOPT_VERBOSE, 1)
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_DEBUGFUNCTION, <void*>debug_function)


    cdef int _check_error(self, int errcode, str args) except -1:
        error = self._get_error(errcode, args)
        if error is not None:
            raise error

    cdef _get_error(self, int errcode, str args):
        if errcode != 0:
            errmsg = (<bytes>self._error_buffer).decode()
            return CurlError(
                f"Failed to {args}, ErrCode: {errcode}, Reason: '{errmsg}'. "
                "This may be a libcurl error, "
                "See https://curl.se/libcurl/c/libcurl-errors.html first for more details.",
                code=errcode,
            )

    cpdef inline int setopt(self, int option, object value) except -1:
        """Wrapper for curl_easy_setopt.
    
        Parameters:
            option: option to set, use the constants from CURLOPT_X enum
            value: value to set, strings will be handled automatically
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

        # Convert value
        cdef:
            void* c_value = NULL
            int value_type = option / 10000 * 10000
            int intval
            bytes bytesval
            int ret
        if value_type == 30000 or value_type == 0:
            # c_value = ffi.new("int*", value)
            intval = <int>value
            c_value = <void*>&intval
        elif option == curl.CURLOPT_WRITEDATA:
            c_value = <void*>value
            self._write_handle = value # store a ref
            curl._curl_easy_setopt(
                self._curl, curl.CURLOPT_WRITEFUNCTION, <void*>buffer_callback
            )
        elif option == curl.CURLOPT_HEADERDATA:
            c_value = <void*>value
            self._header_handle = value # store a ref
            curl._curl_easy_setopt(
                self._curl, curl.CURLOPT_HEADERFUNCTION, <void*>buffer_callback
            )
        elif option == curl.CURLOPT_WRITEFUNCTION:
            c_value = <void*>value
            self._write_handle = value # store a ref
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_WRITEFUNCTION, <void*>write_callback)
            option = curl.CURLOPT_WRITEDATA
        elif option == curl.CURLOPT_HEADERFUNCTION:
            c_value = <void*>value
            self._header_handle = value # store a ref
            curl._curl_easy_setopt(self._curl, curl.CURLOPT_HEADERFUNCTION, <void*>write_callback)
            option = curl.CURLOPT_HEADERDATA
        elif value_type == 10000:
            if isinstance(value, str):
                bytesval = value.encode()
                c_value = <void *> <const char *> bytesval
                # c_value = <void*>PyUnicode_AsUTF8AndSize(value, NULL)
            elif isinstance(value, bytes):
                bytesval = value
                # c_value = <void*><const char*>value
                c_value = <void*><const char *> bytesval
            # Must keep a reference, otherwise may be GCed.
            if option == curl.CURLOPT_POSTFIELDS:
                self._body_handle = bytesval
        else:
            raise NotImplementedError("Option unsupported: %s" % option)

        if option == curl.CURLOPT_HTTPHEADER:
            for header in value:
                self._headers = curl.curl_slist_append(self._headers, <const char*>header)
            ret = curl._curl_easy_setopt(self._curl, option, self._headers)
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
        """Wrapper for curl_easy_getinfo. Gets information in response after curl perform.
    
        Parameters:
            option: option to get info of, use the constants from CurlInfo enum
        """
        # ret_option = {
        #     0x100000: "char**",
        #     0x200000: "long*",
        #     0x300000: "double*",
        #     0x400000: "struct curl_slist **",
        # }
        # ret_cast_option = {
        #     0x100000: ffi.string,
        #     0x200000: int,
        #     0x300000: float,
        # }
        cdef:
            int ret_type
            int ret
            char* charret = NULL
            long longret
            double doubleret
            curl.curl_slist *slistret = NULL
        ret_type = option & 0xF00000
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

    cpdef inline bytes version(self):
        """Get the underlying libcurl version."""
        return <bytes>curl.curl_version()

    cpdef inline int impersonate(self, target: str, bint default_headers = True):
        """Set the browser type to impersonate.
    
        Parameters:
            target: browser to impersonate.
            default_headers: whether to add default headers, like User-Agent.
        """
        cdef bytes data = target.encode()
        return curl.curl_easy_impersonate(self._curl, <const char *>data, default_headers)

    cdef inline int _ensure_cacert(self) except -1:
        if not self._is_cert_set:
            ret = self.setopt(curl.CURLOPT_CAINFO, self._cacert)
            self._check_error(ret, "set cacert")

    cpdef inline int perform(self, clear_headers: bool = True) except -1:
        """Wrapper for curl_easy_perform, performs a curl request.

        Parameters:
            clear_headers: clear header slist used in this perform
        """
        # make sure we set a cacert store
        cdef int ret
        self._ensure_cacert()

        # here we go
        with nogil:
            ret = curl.curl_easy_perform(self._curl)
        try:
            self._check_error(ret, "perform")
            return ret
        finally:
            # cleaning
            self.clean_after_perform(clear_headers)

    cpdef inline clean_after_perform(self, clear_headers: bool = True):
        """Clean up handles and buffers after perform, called at the end of `perform`."""
        self._write_handle = None
        self._header_handle = None
        self._body_handle = None
        if clear_headers:
            if self._headers != NULL:
                curl.curl_slist_free_all(self._headers)
            self._headers = NULL
        # fixme: clean resolve
        if self._resolve != NULL:
            curl.curl_slist_free_all(self._resolve)
            self._resolve = NULL

    cpdef inline Curl duphandle(self):
        """This is not a full copy of entire curl object in python. For example, headers
        handle is not copied, you have to set them again."""
        cdef curl.CURL *new_handle
        with nogil:
            new_handle = curl.curl_easy_duphandle(self._curl)
        if new_handle == NULL:
            raise MemoryError
        c = Curl(self._cacert, self._debug, PyCapsule_New(<void*>new_handle, NULL, NULL))
        return c

    def reset(self):
        """Reset all curl options, wrapper for curl_easy_reset."""
        self._is_cert_set = False
        if self._curl:
            with nogil:
                curl.curl_easy_reset(self._curl)
            self._set_error_buffer()
        if self._resolve != NULL:
            curl.curl_slist_free_all(self._resolve)
            self._resolve = NULL

    def parse_cookie_headers(self, list headers) -> SimpleCookie:
        """Extract cookies.SimpleCookie from header lines.

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
        """Extract reason phrase, like `OK`, `Not Found` from response status line."""
        m = re.match(rb"HTTP/\d\.\d [0-9]{3} (.*)", status_line)
        return m.group(1) if m else b""

    @staticmethod
    def parse_status_line(status_line: bytes) -> tuple:
        """Extract reason phrase, like `OK`, `Not Found` from response status line."""
        m = re.match(rb"HTTP/(\d\.\d) ([0-9]{3}) (.*)", status_line)
        if not m:
            return CurlHttpVersion.V1_0, 0, b""
        if m.group(1) == "2.0":
            http_version = CurlHttpVersion.V2_0
        elif m.group(1) == "1.1":
            http_version = CurlHttpVersion.V1_1
        elif m.group(1) == "1.0":
            http_version = CurlHttpVersion.V1_0
        else:
            http_version = CurlHttpVersion.NONE
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

    def _get_selector(asyncio_loop) -> asyncio.AbstractEventLoop:
        """Get selector-compatible loop

        Returns an object with ``add_reader`` family of methods,
        either the loop itself or a SelectorThread instance.

        Workaround Windows proactor removal of *reader methods.
        """

        if asyncio_loop in _selectors:
            return _selectors[asyncio_loop]

        if not isinstance(asyncio_loop, getattr(asyncio, "ProactorEventLoop", type(None))):
            return asyncio_loop

        warnings.warn(PROACTOR_WARNING, RuntimeWarning)

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
    def _get_selector(loop) -> asyncio.AbstractEventLoop:
        return loop


cdef int timer_function(curl.CURLM *curlm, long timeout_ms, void *clientp) with gil:
    """
    see: https://curl.se/libcurl/c/CURLMOPT_TIMERFUNCTION.html
    """
    cdef AsyncCurl async_curl = <AsyncCurl><object>clientp
    # print("time out in %sms" % timeout_ms)
    if timeout_ms == -1:
        for timer in async_curl._timers:
            timer.cancel()
        async_curl._timers = WeakSet()
    else:
        timer = async_curl.loop.call_later(
            timeout_ms / 1000,
            async_curl.process_data,
            curl.CURL_SOCKET_TIMEOUT,  # -1
            curl.CURL_POLL_NONE,  # 0
        )
        async_curl._timers.add(timer)
    return 0

cdef int socket_function(curl.CURL *curl_, int sockfd, int what, void *clientp, void *socketp) with gil:
    cdef AsyncCurl async_curl = <AsyncCurl><object>clientp
    cdef object loop = async_curl.loop

    if what & curl.CURL_POLL_IN or what & curl.CURL_POLL_OUT or what & curl.CURL_POLL_REMOVE:
        if sockfd in async_curl._sockfds:
            loop.remove_reader(sockfd)
            loop.remove_writer(sockfd)
            async_curl._sockfds.remove(sockfd)
        elif what & curl.CURL_POLL_REMOVE:
            raise TypeError(f"File descriptor {sockfd} not found.")

    if what & curl.CURL_POLL_IN:
        loop.add_reader(sockfd, async_curl.process_data, sockfd, curl.CURL_CSELECT_IN)
        async_curl._sockfds.add(sockfd)
    if what & curl.CURL_POLL_OUT:
        loop.add_writer(sockfd, async_curl.process_data, sockfd, curl.CURL_CSELECT_OUT)
        async_curl._sockfds.add(sockfd)
    return 0

@cython.final
@cython.no_gc
cdef class AsyncCurl:
    cdef:
        curl.CURLM *_curlm
        str _cacert
        dict _curl2future  # Dict[Curl, asyncio.Future]
        dict _curl2curl  #  c curl to Curl
        set _sockfds   # sockfds
        object loop
        object _checker  # asyncio.Task
        object _timers   # WeakSet

    def __cinit__(self, str cacert = DEFAULT_CACERT, object loop=None):
        self._curlm = curl.curl_multi_init()
        if self._curlm == NULL:
            raise MemoryError
        self._cacert = cacert
        self._curl2future = {}  # curl to future map
        self._curl2curl = {}  # c curl to Curl Dict[int, Curl]
        self._sockfds = set()  # sockfds
        self.loop = _get_selector(
            loop if loop is not None else asyncio.get_running_loop()
        )
        self._checker = self.loop.create_task(self._force_timeout())
        self._timers = WeakSet()
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

    cpdef inline close(self):
        """Close and cleanup running timers, readers, writers and handles."""
        # Close force timeout checker
        self._checker.cancel()
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
        for timer in self._timers:
            timer.cancel()

    async def _force_timeout(self):
        while True:
            if not self._curlm:
                break
            await asyncio.sleep(1)
            # print("force timeout")
            self.socket_action(curl.CURL_SOCKET_TIMEOUT, curl.CURL_POLL_NONE)

    cpdef inline add_handle(self, Curl curl_):
        """Add a curl handle to be managed by curl_multi. This is the equivalent of
        `perform` in the async world."""
        # import pdb; pdb.set_trace()
        curl_._ensure_cacert()
        curl.curl_multi_add_handle(self._curlm, curl_._curl)
        future = self.loop.create_future()
        self._curl2future[curl_] = future
        self._curl2curl[<long long><void*>curl_._curl] = curl_
        return future

    cpdef inline int socket_action(self, int sockfd, int ev_bitmask) except -1:
        """Call libcurl socket_action function"""
        cdef int running_handle
        cdef int code
        with nogil:
            code = curl.curl_multi_socket_action(self._curlm, sockfd, ev_bitmask, &running_handle)
        if code != curl.CURLE_OK:
            raise CurlError("failed to call curl_multi_socket_action", code)
        return running_handle

    cpdef inline process_data(self, int sockfd, int ev_bitmask):
        """Call curl_multi_info_read to read data for given socket."""
        if not self._curlm:
            warnings.warn("Curlm alread closed! quitting from process_data")
            return

        self.socket_action(sockfd, ev_bitmask)

        cdef:
            int msg_in_queue
            int retcode
            curl.CURLMsg *curl_msg
            Curl curl_
        while True:
            curl_msg = curl.curl_multi_info_read(self._curlm, &msg_in_queue)
            # print("message in queue", msg_in_queue[0], curl_msg)
            if curl_msg == NULL:
                break
            if curl_msg.msg == curl.CURLMSG_DONE:
                # print("curl_message", curl_msg.msg, curl_msg.data.result)
                curl_ = <Curl>self._curl2curl[<long long><void*>curl_msg.easy_handle]
                retcode = curl_msg.data.result
                if retcode == 0:
                    self.set_result(curl_)
                else:
                    # import pdb; pdb.set_trace()
                    self.set_exception(curl_, curl_._get_error(retcode, "perform"))
            else:
                print("NOT DONE")  # Will not reach, for no other code being defined.

    cdef inline object _pop_future(self, Curl curl_):
        curl.curl_multi_remove_handle(self._curlm, curl_._curl)
        self._curl2curl.pop(<long long><void*>curl_._curl, None)
        return self._curl2future.pop(curl_, None)

    cpdef inline remove_handle(self, Curl curl):
        """Cancel a future for given curl handle."""
        cdef object future = self._pop_future(curl)
        if future and not future.done() and not future.cancelled():
            future.cancel()

    cdef inline set_result(self, Curl curl):
        """Mark a future as done for given curl handle."""
        cdef object future = self._pop_future(curl)
        if future and not future.done() and not future.cancelled():
            future.set_result(None)

    cdef inline set_exception(self, Curl curl, object exception):
        """Raise exception of a future for given curl handle."""
        cdef object future = self._pop_future(curl)
        if future and not future.done() and not future.cancelled():
            future.set_exception(exception)