# This file is automatically generated, do not modify it directly.

from enum import IntEnum


class CurlOpt(IntEnum):
    """``CULROPT_`` constancs extracted from libcurl,
    see: https://curl.se/libcurl/c/curl_easy_setopt.html"""

    WRITEDATA = 10000 + 1
    URL = 10000 + 2
    PORT = 0 + 3
    PROXY = 10000 + 4
    USERPWD = 10000 + 5
    PROXYUSERPWD = 10000 + 6
    RANGE = 10000 + 7
    READDATA = 10000 + 9
    ERRORBUFFER = 10000 + 10
    WRITEFUNCTION = 20000 + 11
    READFUNCTION = 20000 + 12
    TIMEOUT = 0 + 13
    INFILESIZE = 0 + 14
    POSTFIELDS = 10000 + 15
    REFERER = 10000 + 16
    FTPPORT = 10000 + 17
    USERAGENT = 10000 + 18
    LOW_SPEED_LIMIT = 0 + 19
    LOW_SPEED_TIME = 0 + 20
    RESUME_FROM = 0 + 21
    COOKIE = 10000 + 22
    HTTPHEADER = 10000 + 23
    HTTPPOST = 10000 + 24
    SSLCERT = 10000 + 25
    KEYPASSWD = 10000 + 26
    CRLF = 0 + 27
    QUOTE = 10000 + 28
    HEADERDATA = 10000 + 29
    COOKIEFILE = 10000 + 31
    SSLVERSION = 0 + 32
    TIMECONDITION = 0 + 33
    TIMEVALUE = 0 + 34
    CUSTOMREQUEST = 10000 + 36
    STDERR = 10000 + 37
    POSTQUOTE = 10000 + 39
    OBSOLETE40 = 10000 + 40
    VERBOSE = 0 + 41
    HEADER = 0 + 42
    NOPROGRESS = 0 + 43
    NOBODY = 0 + 44
    FAILONERROR = 0 + 45
    UPLOAD = 0 + 46
    POST = 0 + 47
    DIRLISTONLY = 0 + 48
    APPEND = 0 + 50
    NETRC = 0 + 51
    FOLLOWLOCATION = 0 + 52
    TRANSFERTEXT = 0 + 53
    PUT = 0 + 54
    PROGRESSFUNCTION = 20000 + 56
    XFERINFODATA = 10000 + 57
    AUTOREFERER = 0 + 58
    PROXYPORT = 0 + 59
    POSTFIELDSIZE = 0 + 60
    HTTPPROXYTUNNEL = 0 + 61
    INTERFACE = 10000 + 62
    KRBLEVEL = 10000 + 63
    SSL_VERIFYPEER = 0 + 64
    CAINFO = 10000 + 65
    MAXREDIRS = 0 + 68
    FILETIME = 0 + 69
    TELNETOPTIONS = 10000 + 70
    MAXCONNECTS = 0 + 71
    OBSOLETE72 = 0 + 72
    FRESH_CONNECT = 0 + 74
    FORBID_REUSE = 0 + 75
    RANDOM_FILE = 10000 + 76
    EGDSOCKET = 10000 + 77
    CONNECTTIMEOUT = 0 + 78
    HEADERFUNCTION = 20000 + 79
    HTTPGET = 0 + 80
    SSL_VERIFYHOST = 0 + 81
    COOKIEJAR = 10000 + 82
    SSL_CIPHER_LIST = 10000 + 83
    HTTP_VERSION = 0 + 84
    FTP_USE_EPSV = 0 + 85
    SSLCERTTYPE = 10000 + 86
    SSLKEY = 10000 + 87
    SSLKEYTYPE = 10000 + 88
    SSLENGINE = 10000 + 89
    SSLENGINE_DEFAULT = 0 + 90
    DNS_USE_GLOBAL_CACHE = 0 + 91
    DNS_CACHE_TIMEOUT = 0 + 92
    PREQUOTE = 10000 + 93
    DEBUGFUNCTION = 20000 + 94
    DEBUGDATA = 10000 + 95
    COOKIESESSION = 0 + 96
    CAPATH = 10000 + 97
    BUFFERSIZE = 0 + 98
    NOSIGNAL = 0 + 99
    SHARE = 10000 + 100
    PROXYTYPE = 0 + 101
    ACCEPT_ENCODING = 10000 + 102
    PRIVATE = 10000 + 103
    HTTP200ALIASES = 10000 + 104
    UNRESTRICTED_AUTH = 0 + 105
    FTP_USE_EPRT = 0 + 106
    HTTPAUTH = 0 + 107
    SSL_CTX_FUNCTION = 20000 + 108
    SSL_CTX_DATA = 10000 + 109
    FTP_CREATE_MISSING_DIRS = 0 + 110
    PROXYAUTH = 0 + 111
    SERVER_RESPONSE_TIMEOUT = 0 + 112
    IPRESOLVE = 0 + 113
    MAXFILESIZE = 0 + 114
    INFILESIZE_LARGE = 30000 + 115
    RESUME_FROM_LARGE = 30000 + 116
    MAXFILESIZE_LARGE = 30000 + 117
    NETRC_FILE = 10000 + 118
    USE_SSL = 0 + 119
    POSTFIELDSIZE_LARGE = 30000 + 120
    TCP_NODELAY = 0 + 121
    FTPSSLAUTH = 0 + 129
    IOCTLFUNCTION = 20000 + 130
    IOCTLDATA = 10000 + 131
    FTP_ACCOUNT = 10000 + 134
    COOKIELIST = 10000 + 135
    IGNORE_CONTENT_LENGTH = 0 + 136
    FTP_SKIP_PASV_IP = 0 + 137
    FTP_FILEMETHOD = 0 + 138
    LOCALPORT = 0 + 139
    LOCALPORTRANGE = 0 + 140
    CONNECT_ONLY = 0 + 141
    CONV_FROM_NETWORK_FUNCTION = 20000 + 142
    CONV_TO_NETWORK_FUNCTION = 20000 + 143
    CONV_FROM_UTF8_FUNCTION = 20000 + 144
    MAX_SEND_SPEED_LARGE = 30000 + 145
    MAX_RECV_SPEED_LARGE = 30000 + 146
    FTP_ALTERNATIVE_TO_USER = 10000 + 147
    SOCKOPTFUNCTION = 20000 + 148
    SOCKOPTDATA = 10000 + 149
    SSL_SESSIONID_CACHE = 0 + 150
    SSH_AUTH_TYPES = 0 + 151
    SSH_PUBLIC_KEYFILE = 10000 + 152
    SSH_PRIVATE_KEYFILE = 10000 + 153
    FTP_SSL_CCC = 0 + 154
    TIMEOUT_MS = 0 + 155
    CONNECTTIMEOUT_MS = 0 + 156
    HTTP_TRANSFER_DECODING = 0 + 157
    HTTP_CONTENT_DECODING = 0 + 158
    NEW_FILE_PERMS = 0 + 159
    NEW_DIRECTORY_PERMS = 0 + 160
    POSTREDIR = 0 + 161
    SSH_HOST_PUBLIC_KEY_MD5 = 10000 + 162
    OPENSOCKETFUNCTION = 20000 + 163
    OPENSOCKETDATA = 10000 + 164
    COPYPOSTFIELDS = 10000 + 165
    PROXY_TRANSFER_MODE = 0 + 166
    SEEKFUNCTION = 20000 + 167
    SEEKDATA = 10000 + 168
    CRLFILE = 10000 + 169
    ISSUERCERT = 10000 + 170
    ADDRESS_SCOPE = 0 + 171
    CERTINFO = 0 + 172
    USERNAME = 10000 + 173
    PASSWORD = 10000 + 174
    PROXYUSERNAME = 10000 + 175
    PROXYPASSWORD = 10000 + 176
    NOPROXY = 10000 + 177
    TFTP_BLKSIZE = 0 + 178
    SOCKS5_GSSAPI_SERVICE = 10000 + 179
    SOCKS5_GSSAPI_NEC = 0 + 180
    PROTOCOLS = 0 + 181
    REDIR_PROTOCOLS = 0 + 182
    SSH_KNOWNHOSTS = 10000 + 183
    SSH_KEYFUNCTION = 20000 + 184
    SSH_KEYDATA = 10000 + 185
    MAIL_FROM = 10000 + 186
    MAIL_RCPT = 10000 + 187
    FTP_USE_PRET = 0 + 188
    RTSP_REQUEST = 0 + 189
    RTSP_SESSION_ID = 10000 + 190
    RTSP_STREAM_URI = 10000 + 191
    RTSP_TRANSPORT = 10000 + 192
    RTSP_CLIENT_CSEQ = 0 + 193
    RTSP_SERVER_CSEQ = 0 + 194
    INTERLEAVEDATA = 10000 + 195
    INTERLEAVEFUNCTION = 20000 + 196
    WILDCARDMATCH = 0 + 197
    CHUNK_BGN_FUNCTION = 20000 + 198
    CHUNK_END_FUNCTION = 20000 + 199
    FNMATCH_FUNCTION = 20000 + 200
    CHUNK_DATA = 10000 + 201
    FNMATCH_DATA = 10000 + 202
    RESOLVE = 10000 + 203
    TLSAUTH_USERNAME = 10000 + 204
    TLSAUTH_PASSWORD = 10000 + 205
    TLSAUTH_TYPE = 10000 + 206
    TRANSFER_ENCODING = 0 + 207
    CLOSESOCKETFUNCTION = 20000 + 208
    CLOSESOCKETDATA = 10000 + 209
    GSSAPI_DELEGATION = 0 + 210
    DNS_SERVERS = 10000 + 211
    ACCEPTTIMEOUT_MS = 0 + 212
    TCP_KEEPALIVE = 0 + 213
    TCP_KEEPIDLE = 0 + 214
    TCP_KEEPINTVL = 0 + 215
    SSL_OPTIONS = 0 + 216
    MAIL_AUTH = 10000 + 217
    SASL_IR = 0 + 218
    XFERINFOFUNCTION = 20000 + 219
    XOAUTH2_BEARER = 10000 + 220
    DNS_INTERFACE = 10000 + 221
    DNS_LOCAL_IP4 = 10000 + 222
    DNS_LOCAL_IP6 = 10000 + 223
    LOGIN_OPTIONS = 10000 + 224
    SSL_ENABLE_NPN = 0 + 225
    SSL_ENABLE_ALPN = 0 + 226
    EXPECT_100_TIMEOUT_MS = 0 + 227
    PROXYHEADER = 10000 + 228
    HEADEROPT = 0 + 229
    PINNEDPUBLICKEY = 10000 + 230
    UNIX_SOCKET_PATH = 10000 + 231
    SSL_VERIFYSTATUS = 0 + 232
    SSL_FALSESTART = 0 + 233
    PATH_AS_IS = 0 + 234
    PROXY_SERVICE_NAME = 10000 + 235
    SERVICE_NAME = 10000 + 236
    PIPEWAIT = 0 + 237
    DEFAULT_PROTOCOL = 10000 + 238
    STREAM_WEIGHT = 0 + 239
    STREAM_DEPENDS = 10000 + 240
    STREAM_DEPENDS_E = 10000 + 241
    TFTP_NO_OPTIONS = 0 + 242
    CONNECT_TO = 10000 + 243
    TCP_FASTOPEN = 0 + 244
    KEEP_SENDING_ON_ERROR = 0 + 245
    PROXY_CAINFO = 10000 + 246
    PROXY_CAPATH = 10000 + 247
    PROXY_SSL_VERIFYPEER = 0 + 248
    PROXY_SSL_VERIFYHOST = 0 + 249
    PROXY_SSLVERSION = 0 + 250
    PROXY_TLSAUTH_USERNAME = 10000 + 251
    PROXY_TLSAUTH_PASSWORD = 10000 + 252
    PROXY_TLSAUTH_TYPE = 10000 + 253
    PROXY_SSLCERT = 10000 + 254
    PROXY_SSLCERTTYPE = 10000 + 255
    PROXY_SSLKEY = 10000 + 256
    PROXY_SSLKEYTYPE = 10000 + 257
    PROXY_KEYPASSWD = 10000 + 258
    PROXY_SSL_CIPHER_LIST = 10000 + 259
    PROXY_CRLFILE = 10000 + 260
    PROXY_SSL_OPTIONS = 0 + 261
    PRE_PROXY = 10000 + 262
    PROXY_PINNEDPUBLICKEY = 10000 + 263
    ABSTRACT_UNIX_SOCKET = 10000 + 264
    SUPPRESS_CONNECT_HEADERS = 0 + 265
    REQUEST_TARGET = 10000 + 266
    SOCKS5_AUTH = 0 + 267
    SSH_COMPRESSION = 0 + 268
    MIMEPOST = 10000 + 269
    TIMEVALUE_LARGE = 30000 + 270
    HAPPY_EYEBALLS_TIMEOUT_MS = 0 + 271
    RESOLVER_START_FUNCTION = 20000 + 272
    RESOLVER_START_DATA = 10000 + 273
    HAPROXYPROTOCOL = 0 + 274
    DNS_SHUFFLE_ADDRESSES = 0 + 275
    TLS13_CIPHERS = 10000 + 276
    PROXY_TLS13_CIPHERS = 10000 + 277
    DISALLOW_USERNAME_IN_URL = 0 + 278
    DOH_URL = 10000 + 279
    UPLOAD_BUFFERSIZE = 0 + 280
    UPKEEP_INTERVAL_MS = 0 + 281
    CURLU = 10000 + 282
    TRAILERFUNCTION = 20000 + 283
    TRAILERDATA = 10000 + 284
    HTTP09_ALLOWED = 0 + 285
    ALTSVC_CTRL = 0 + 286
    ALTSVC = 10000 + 287
    MAXAGE_CONN = 0 + 288
    SASL_AUTHZID = 10000 + 289
    MAIL_RCPT_ALLLOWFAILS = 0 + 290
    SSLCERT_BLOB = 40000 + 291
    SSLKEY_BLOB = 40000 + 292
    PROXY_SSLCERT_BLOB = 40000 + 293
    PROXY_SSLKEY_BLOB = 40000 + 294
    ISSUERCERT_BLOB = 40000 + 295
    PROXY_ISSUERCERT = 10000 + 296
    PROXY_ISSUERCERT_BLOB = 40000 + 297
    SSL_EC_CURVES = 10000 + 298
    HSTS_CTRL = 0 + 299
    HSTS = 10000 + 300
    HSTSREADFUNCTION = 20000 + 301
    HSTSREADDATA = 10000 + 302
    HSTSWRITEFUNCTION = 20000 + 303
    HSTSWRITEDATA = 10000 + 304
    AWS_SIGV4 = 10000 + 305
    DOH_SSL_VERIFYPEER = 0 + 306
    DOH_SSL_VERIFYHOST = 0 + 307
    DOH_SSL_VERIFYSTATUS = 0 + 308
    CAINFO_BLOB = 40000 + 309
    PROXY_CAINFO_BLOB = 40000 + 310
    SSH_HOST_PUBLIC_KEY_SHA256 = 10000 + 311
    PREREQFUNCTION = 20000 + 312
    PREREQDATA = 10000 + 313
    MAXLIFETIME_CONN = 0 + 314
    MIME_OPTIONS = 0 + 315
    SSH_HOSTKEYFUNCTION = 20000 + 316
    SSH_HOSTKEYDATA = 10000 + 317
    PROTOCOLS_STR = 10000 + 318
    REDIR_PROTOCOLS_STR = 10000 + 319
    WS_OPTIONS = 0 + 320
    CA_CACHE_TIMEOUT = 0 + 321
    QUICK_EXIT = 0 + 322
    HTTPBASEHEADER = 10000 + 323
    SSL_SIG_HASH_ALGS = 10000 + 324
    SSL_ENABLE_ALPS = 0 + 325
    SSL_CERT_COMPRESSION = 10000 + 326
    SSL_ENABLE_TICKET = 0 + 327
    HTTP2_PSEUDO_HEADERS_ORDER = 10000 + 328
    HTTP2_SETTINGS = 10000 + 329
    SSL_PERMUTE_EXTENSIONS = 0 + 330
    HTTP2_WINDOW_UPDATE = 0 + 331
    ECH = 10000 + 332

    if locals().get("WRITEDATA"):
        FILE = locals().get("WRITEDATA")
    if locals().get("READDATA"):
        INFILE = locals().get("READDATA")
    if locals().get("HEADERDATA"):
        WRITEHEADER = locals().get("HEADERDATA")


class CurlInfo(IntEnum):
    """``CURLINFO_`` constancs extracted from libcurl,
    see: https://curl.se/libcurl/c/curl_easy_getinfo.html"""

    TEXT = 0
    EFFECTIVE_URL = 0x100000 + 1
    RESPONSE_CODE = 0x200000 + 2
    TOTAL_TIME = 0x300000 + 3
    NAMELOOKUP_TIME = 0x300000 + 4
    CONNECT_TIME = 0x300000 + 5
    PRETRANSFER_TIME = 0x300000 + 6
    SIZE_UPLOAD_T = 0x600000 + 7
    SIZE_DOWNLOAD_T = 0x600000 + 8
    SPEED_DOWNLOAD_T = 0x600000 + 9
    SPEED_UPLOAD_T = 0x600000 + 10
    HEADER_SIZE = 0x200000 + 11
    REQUEST_SIZE = 0x200000 + 12
    SSL_VERIFYRESULT = 0x200000 + 13
    FILETIME = 0x200000 + 14
    FILETIME_T = 0x600000 + 14
    CONTENT_LENGTH_DOWNLOAD_T = 0x600000 + 15
    CONTENT_LENGTH_UPLOAD_T = 0x600000 + 16
    STARTTRANSFER_TIME = 0x300000 + 17
    CONTENT_TYPE = 0x100000 + 18
    REDIRECT_TIME = 0x300000 + 19
    REDIRECT_COUNT = 0x200000 + 20
    PRIVATE = 0x100000 + 21
    HTTP_CONNECTCODE = 0x200000 + 22
    HTTPAUTH_AVAIL = 0x200000 + 23
    PROXYAUTH_AVAIL = 0x200000 + 24
    OS_ERRNO = 0x200000 + 25
    NUM_CONNECTS = 0x200000 + 26
    SSL_ENGINES = 0x400000 + 27
    COOKIELIST = 0x400000 + 28
    FTP_ENTRY_PATH = 0x100000 + 30
    REDIRECT_URL = 0x100000 + 31
    PRIMARY_IP = 0x100000 + 32
    APPCONNECT_TIME = 0x300000 + 33
    CERTINFO = 0x400000 + 34
    CONDITION_UNMET = 0x200000 + 35
    RTSP_SESSION_ID = 0x100000 + 36
    RTSP_CLIENT_CSEQ = 0x200000 + 37
    RTSP_SERVER_CSEQ = 0x200000 + 38
    RTSP_CSEQ_RECV = 0x200000 + 39
    PRIMARY_PORT = 0x200000 + 40
    LOCAL_IP = 0x100000 + 41
    LOCAL_PORT = 0x200000 + 42
    ACTIVESOCKET = 0x500000 + 44
    TLS_SSL_PTR = 0x400000 + 45
    HTTP_VERSION = 0x200000 + 46
    PROXY_SSL_VERIFYRESULT = 0x200000 + 47
    SCHEME = 0x100000 + 49
    TOTAL_TIME_T = 0x600000 + 50
    NAMELOOKUP_TIME_T = 0x600000 + 51
    CONNECT_TIME_T = 0x600000 + 52
    PRETRANSFER_TIME_T = 0x600000 + 53
    STARTTRANSFER_TIME_T = 0x600000 + 54
    REDIRECT_TIME_T = 0x600000 + 55
    APPCONNECT_TIME_T = 0x600000 + 56
    RETRY_AFTER = 0x600000 + 57
    EFFECTIVE_METHOD = 0x100000 + 58
    PROXY_ERROR = 0x200000 + 59
    REFERER = 0x100000 + 60
    CAINFO = 0x100000 + 61
    CAPATH = 0x100000 + 62
    LASTONE = 62

    if locals().get("RESPONSE_CODE"):
        HTTP_CODE = locals().get("RESPONSE_CODE")


class CurlMOpt(IntEnum):
    """``CURLMOPT_`` constancs extracted from libcurl,
    see: https://curl.se/libcurl/c/curl_multi_setopt.html"""

    SOCKETFUNCTION = 20000 + 1
    SOCKETDATA = 10000 + 2
    PIPELINING = 0 + 3
    TIMERFUNCTION = 20000 + 4
    TIMERDATA = 10000 + 5
    MAXCONNECTS = 0 + 6
    MAX_HOST_CONNECTIONS = 0 + 7
    MAX_PIPELINE_LENGTH = 0 + 8
    CONTENT_LENGTH_PENALTY_SIZE = 30000 + 9
    CHUNK_LENGTH_PENALTY_SIZE = 30000 + 10
    PIPELINING_SITE_BL = 10000 + 11
    PIPELINING_SERVER_BL = 10000 + 12
    MAX_TOTAL_CONNECTIONS = 0 + 13
    PUSHFUNCTION = 20000 + 14
    PUSHDATA = 10000 + 15
    MAX_CONCURRENT_STREAMS = 0 + 16


class CurlECode(IntEnum):
    """``CURLECODE_`` constancs extracted from libcurl,
    see: https://curl.se/libcurl/c/libcurl-errors.html"""

    OK = 0
    UNSUPPORTED_PROTOCOL = 1
    FAILED_INIT = 2
    URL_MALFORMAT = 3
    NOT_BUILT_IN = 4
    COULDNT_RESOLVE_PROXY = 5
    COULDNT_RESOLVE_HOST = 6
    COULDNT_CONNECT = 7
    WEIRD_SERVER_REPLY = 8
    REMOTE_ACCESS_DENIED = 9
    FTP_ACCEPT_FAILED = 10
    FTP_WEIRD_PASS_REPLY = 11
    FTP_ACCEPT_TIMEOUT = 12
    FTP_WEIRD_PASV_REPLY = 13
    FTP_WEIRD_227_FORMAT = 14
    FTP_CANT_GET_HOST = 15
    HTTP2 = 16
    FTP_COULDNT_SET_TYPE = 17
    PARTIAL_FILE = 18
    FTP_COULDNT_RETR_FILE = 19
    OBSOLETE20 = 20
    QUOTE_ERROR = 21
    HTTP_RETURNED_ERROR = 22
    WRITE_ERROR = 23
    OBSOLETE24 = 24
    UPLOAD_FAILED = 25
    READ_ERROR = 26
    OUT_OF_MEMORY = 27
    OPERATION_TIMEDOUT = 28
    OBSOLETE29 = 29
    FTP_PORT_FAILED = 30
    FTP_COULDNT_USE_REST = 31
    OBSOLETE32 = 32
    RANGE_ERROR = 33
    HTTP_POST_ERROR = 34
    SSL_CONNECT_ERROR = 35
    BAD_DOWNLOAD_RESUME = 36
    FILE_COULDNT_READ_FILE = 37
    LDAP_CANNOT_BIND = 38
    LDAP_SEARCH_FAILED = 39
    OBSOLETE40 = 40
    FUNCTION_NOT_FOUND = 41
    ABORTED_BY_CALLBACK = 42
    BAD_FUNCTION_ARGUMENT = 43
    OBSOLETE44 = 44
    INTERFACE_FAILED = 45
    OBSOLETE46 = 46
    TOO_MANY_REDIRECTS = 47
    UNKNOWN_OPTION = 48
    SETOPT_OPTION_SYNTAX = 49
    OBSOLETE50 = 50
    OBSOLETE51 = 51
    GOT_NOTHING = 52
    SSL_ENGINE_NOTFOUND = 53
    SSL_ENGINE_SETFAILED = 54
    SEND_ERROR = 55
    RECV_ERROR = 56
    OBSOLETE57 = 57
    SSL_CERTPROBLEM = 58
    SSL_CIPHER = 59
    PEER_FAILED_VERIFICATION = 60
    BAD_CONTENT_ENCODING = 61
    OBSOLETE62 = 62
    FILESIZE_EXCEEDED = 63
    USE_SSL_FAILED = 64
    SEND_FAIL_REWIND = 65
    SSL_ENGINE_INITFAILED = 66
    LOGIN_DENIED = 67
    TFTP_NOTFOUND = 68
    TFTP_PERM = 69
    REMOTE_DISK_FULL = 70
    TFTP_ILLEGAL = 71
    TFTP_UNKNOWNID = 72
    REMOTE_FILE_EXISTS = 73
    TFTP_NOSUCHUSER = 74
    OBSOLETE75 = 75
    OBSOLETE76 = 76
    SSL_CACERT_BADFILE = 77
    REMOTE_FILE_NOT_FOUND = 78
    SSH = 79
    SSL_SHUTDOWN_FAILED = 80
    AGAIN = 81
    SSL_CRL_BADFILE = 82
    SSL_ISSUER_ERROR = 83
    FTP_PRET_FAILED = 84
    RTSP_CSEQ_ERROR = 85
    RTSP_SESSION_ERROR = 86
    FTP_BAD_FILE_LIST = 87
    CHUNK_FAILED = 88
    NO_CONNECTION_AVAILABLE = 89
    SSL_PINNEDPUBKEYNOTMATCH = 90
    SSL_INVALIDCERTSTATUS = 91
    HTTP2_STREAM = 92
    RECURSIVE_API_CALL = 93
    AUTH_ERROR = 94
    HTTP3 = 95
    QUIC_CONNECT_ERROR = 96
    PROXY = 97
    SSL_CLIENTCERT = 98
    UNRECOVERABLE_POLL = 99
    ECH_REQUIRED = 100


class CurlHttpVersion(IntEnum):
    """``CURL_HTTP_VERSION`` constants extracted from libcurl, see comments for details"""

    NONE = 0
    V1_0 = 1  # please use HTTP 1.0 in the request */
    V1_1 = 2  # please use HTTP 1.1 in the request */
    V2_0 = 3  # please use HTTP 2 in the request */
    V2TLS = 4  # use version 2 for HTTPS, version 1.1 for HTTP */
    V2_PRIOR_KNOWLEDGE = 5  # please use HTTP 2 without HTTP/1.1 Upgrade */
    V3 = 30  # Makes use of explicit HTTP/3 without fallback.


class CurlWsFlag(IntEnum):
    """``CURL_WS_FLAG`` constancs extracted from libcurl, see comments for details"""

    TEXT = 1 << 0
    BINARY = 1 << 1
    CONT = 1 << 2
    CLOSE = 1 << 3
    PING = 1 << 4
    OFFSET = 1 << 5
