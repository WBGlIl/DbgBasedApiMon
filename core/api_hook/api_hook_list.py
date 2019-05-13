# -*- coding: utf-8 -*-

"""
1. 为保持此文件的整洁, 辅助函数移入 utils_dbg.py
"""

# from core import dbg # 这里不需要吧??

from api_hook_def import *
from api_hook_callbacks import *


# ---------------------------------------------------------------------------
# util


# ---------------------------------------------------------------------------
# api 断点对象定义
# ---------------------------------------------------------------------------


"""

hook_ = ApiHookLogParams(
    "", "", group_name="", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[]
)

hook_ = ApiHookCustom(
    "", "", handler_api_invoke=, group_name="",
    weight=V_WEIGHT_MIDDLE
)

"""


# ---------------------------------------------------------------------------
# 注册表 - advapi32.dll


hook_RegCreateKeyExA = ApiHookLogParams(
    "advapi32.dll", "RegCreateKeyExA", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)],
    cstk_filter_depth=2
)

hook_RegCreateKeyExW = ApiHookLogParams(
    "advapi32.dll", "RegCreateKeyExW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2
)

hook_RegConnectRegistryW = ApiHookLogParams(
    "advapi32.dll", "RegConnectRegistryW", group_name="reg_advapi32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "key", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2
)

hook_RegSetValueExA = ApiHookCustom(
    "advapi32.dll", "RegSetValueExA", handler_api_invoke=handler_RegSetValueExA, group_name="reg_advapi32",
    weight=V_WEIGHT_HIGH, cstk_filter_depth=2
)

hook_RegSetValueExW = ApiHookCustom(
    "advapi32.dll", "RegSetValueExW", handler_api_invoke=handler_RegSetValueExW, group_name="reg_advapi32",
    weight=V_WEIGHT_HIGH, cstk_filter_depth=2
)

hook_RegDeleteKeyA = ApiHookLogParams(
    "advapi32.dll", "RegDeleteKeyA", group_name="reg_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]
)

hook_RegDeleteKeyW = ApiHookLogParams(
    "advapi32.dll", "RegDeleteKeyW", group_name="reg_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]
)

hook_RegDeleteValueA = ApiHookLogParams(
    "advapi32.dll", "RegDeleteValueA", group_name="reg_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]
)

hook_RegDeleteValueW = ApiHookLogParams(
    "advapi32.dll", "RegDeleteValueW", group_name="reg_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]
)

hook_RegSaveKeyExA = ApiHookLogParams(
    "advapi32.dll", "RegSaveKeyExA", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]
)

hook_RegSaveKeyExW = ApiHookLogParams(
    "advapi32.dll", "RegSaveKeyExW", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]
)

hook_RegSaveKeyA = ApiHookLogParams(
    "advapi32.dll", "RegSaveKeyA", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]
)

hook_RegSaveKeyW = ApiHookLogParams(
    "advapi32.dll", "RegSaveKeyW", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]
)

hook_RegReplaceKeyA = ApiHookLogParams(
    "advapi32.dll", "RegReplaceKeyA", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "file_new", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "file_old", V_PARAM_LOG_PASTR)]
)

hook_RegReplaceKeyW = ApiHookLogParams(
    "advapi32.dll", "RegReplaceKeyW", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "file_new", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "file_old", V_PARAM_LOG_PUSTR)]
)

hook_RegRestoreKeyA = ApiHookLogParams(
    "advapi32.dll", "RegRestoreKeyA", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]
)

hook_RegRestoreKeyW = ApiHookLogParams(
    "advapi32.dll", "RegRestoreKeyW", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]
)

hook_RegLoadKeyA = ApiHookLogParams(
    "advapi32.dll", "RegLoadKeyA", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PASTR)]
)

hook_RegLoadKeyW = ApiHookLogParams(
    "advapi32.dll", "RegLoadKeyW", group_name="reg_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)]
)

hook_RegOpenKeyExA = ApiHookLogParams(
    "advapi32.dll", "RegOpenKeyExA", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_RegOpenKeyExW = ApiHookLogParams(
    "advapi32.dll", "RegOpenKeyExW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_RegQueryInfoKeyA = ApiHookLogParams(
    "advapi32.dll", "RegQueryInfoKeyA", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegQueryInfoKeyW = ApiHookLogParams(
    "advapi32.dll", "RegQueryInfoKeyW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegQueryMultipleValuesA = ApiHookLogParams(
    "advapi32.dll", "RegQueryMultipleValuesA", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegQueryMultipleValuesW = ApiHookLogParams(
    "advapi32.dll", "RegQueryMultipleValuesW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegQueryValueExA = ApiHookLogParams(
    "advapi32.dll", "RegQueryValueExA", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "vname", V_PARAM_LOG_PASTR)],
    cstk_filter_depth=2, max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegQueryValueExW = ApiHookLogParams(
    "advapi32.dll", "RegQueryValueExW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "vname", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegEnumKeyExA = ApiHookLogParams(
    "advapi32.dll", "RegEnumKeyExA", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    cstk_filter_depth=2, max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegEnumKeyW = ApiHookLogParams(
    "advapi32.dll", "RegEnumKeyW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegEnumKeyExW = ApiHookLogParams(
    "advapi32.dll", "RegEnumKeyExW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegEnumValueA = ApiHookLogParams(
    "advapi32.dll", "RegEnumValueA", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)

hook_RegEnumValueW = ApiHookLogParams(
    "advapi32.dll", "RegEnumValueW", group_name="reg_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    max_invoke_cnt_runtime=10, is_fragile=True
)


# ---------------------------------------------------------------------------
# DNS - dnsapi.dll


hook_DnsQuery_W = ApiHookLogParams(
    "dnsapi.dll", "DnsQuery_W", group_name="dns_dnsapi", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)], cstk_filter_depth=4
)

hook_DnsQuery_UTF8 = ApiHookLogParams(
    "dnsapi.dll", "DnsQuery_UTF8", group_name="dns_dnsapi", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "name", V_PARAM_LOG_PASTR)]
)


# ---------------------------------------------------------------------------
# socket - ws2_32.dll


hook_WSAStartup = ApiHookLogParams(
    "ws2_32.dll", "WSAStartup", group_name="sock_ws2_32", weight=V_WEIGHT_CRITICAL
)

hook_WSACleanup = ApiHookLogParams(
    "ws2_32.dll", "WSACleanup", group_name="sock_ws2_32", weight=V_WEIGHT_IGNORE
)

hook_WSASocketW = ApiHookCustom(
    "ws2_32.dll", "WSASocketW", handler_api_invoke=handler_WSASocketW, group_name="sock_ws2_32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=2
)

hook_closesocket = ApiHookLogParams(
    "ws2_32.dll", "closesocket", group_name="sock_ws2_32", weight=V_WEIGHT_IGNORE
)

hook_getnameinfo = ApiHookLogParams(
    "ws2_32.dll", "getnameinfo", group_name="sock_ws2_32", weight=V_WEIGHT_LOW
)

hook_GetNameInfoW = ApiHookLogParams(
    "ws2_32.dll", "GetNameInfoW", group_name="sock_ws2_32", weight=V_WEIGHT_LOW
)

hook_getsockname = ApiHookCustom(
    "ws2_32.dll", "getsockname", handler_api_invoke=handler_getsockname, group_name="sock_ws2_32",
    weight=V_WEIGHT_MIDDLE
)

hook_getpeername = ApiHookLogParams(
    "ws2_32.dll", "getpeername", group_name="sock_ws2_32", weight=V_WEIGHT_LOW
)

hook_gethostname = ApiHookCustom(
    "ws2_32.dll", "gethostname", handler_api_invoke=handler_gethostname, group_name="sock_ws2_32",
    weight=V_WEIGHT_HIGH
)

hook_gethostbyaddr = ApiHookLogParams(
    "ws2_32.dll", "gethostbyaddr", group_name="sock_ws2_32", weight=V_WEIGHT_LOW
)

hook_gethostbyname = ApiHookCustom(
    "ws2_32.dll", "gethostbyname", handler_api_invoke=handler_gethostbyname, group_name="sock_ws2_32",
    weight=V_WEIGHT_HIGH
)

hook_getaddrinfo = ApiHookLogParams(
    "ws2_32.dll", "getaddrinfo", group_name="sock_ws2_32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "node", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "svc", V_PARAM_LOG_PASTR)]
)

hook_GetAddrInfoW = ApiHookLogParams(
    "ws2_32.dll", "GetAddrInfoW", group_name="sock_ws2_32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "node", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "svc", V_PARAM_LOG_PUSTR)]
)

hook_freeaddrinfo = ApiHookLogParams(
    "ws2_32.dll", "freeaddrinfo", group_name="sock_ws2_32", weight=V_WEIGHT_LOW
)

hook_bind = ApiHookCustom(
    "ws2_32.dll", "bind", handler_api_invoke=handler_bind, group_name="sock_ws2_32",
    weight=V_WEIGHT_CRITICAL
)

hook_listen = ApiHookLogParams(
    "ws2_32.dll", "listen", group_name="sock_ws2_32", weight=V_WEIGHT_CRITICAL
)

hook_connect = ApiHookCustom(
    "ws2_32.dll", "connect", handler_api_invoke=handler_connect, group_name="sock_ws2_32",
    weight=V_WEIGHT_CRITICAL
)

hook_send = ApiHookCustom(
    "ws2_32.dll", "send", handler_api_invoke=handler_send, group_name="sock_ws2_32",
    weight=V_WEIGHT_CRITICAL
)

hook_sendto = ApiHookCustom(
    "ws2_32.dll", "sendto", handler_api_invoke=handler_sendto, group_name="sock_ws2_32",
    weight=V_WEIGHT_CRITICAL
)

hook_recv = ApiHookCustom(
    "ws2_32.dll", "recv", handler_api_invoke=handler_recv, group_name="sock_ws2_32",
    weight=V_WEIGHT_CRITICAL
)

hook_recvfrom = ApiHookCustom(
    "ws2_32.dll", "recvfrom", handler_api_invoke=handler_recvfrom, group_name="sock_ws2_32",
    weight=V_WEIGHT_CRITICAL
)

hook_select = ApiHookCustom(
    "ws2_32.dll", "select", handler_api_invoke=handler_select, group_name="sock_ws2_32",
    weight=V_WEIGHT_MIDDLE
)

hook_setsockopt = ApiHookCustom(
    "ws2_32.dll", "setsockopt", handler_api_invoke=handler_setsockopt, group_name="sock_ws2_32",
    weight=V_WEIGHT_MIDDLE
)

hook_WSAAccept = ApiHookLogParams(
    "ws2_32.dll", "", group_name="sock_ws2_32_WSA", weight=V_WEIGHT_CRITICAL,
    cstk_filter_depth=2
)

hook_WSASend = ApiHookCustom(
    "ws2_32.dll", "WSASend", handler_api_invoke=handler_WSASend, group_name="sock_ws2_32_WSA",
    weight=V_WEIGHT_CRITICAL
)

hook_WSASendTo = ApiHookCustom(
    "ws2_32.dll", "WSASendTo", handler_api_invoke=handler_WSASendTo, group_name="sock_ws2_32_WSA",
    weight=V_WEIGHT_CRITICAL
)

hook_WSAConnect = ApiHookCustom(
    "ws2_32.dll", "WSAConnect", handler_api_invoke=handler_WSAConnect, group_name="sock_ws2_32_WSA",
    weight=V_WEIGHT_CRITICAL
)

hook_WSASendDisconnect = ApiHookLogParams(
    "ws2_32.dll", "WSASendDisconnect", group_name="sock_ws2_32_WSA", weight=V_WEIGHT_LOW
)

hook_WSARecv = ApiHookCustom(
    "ws2_32.dll", "WSARecv", handler_api_invoke=handler_WSARecv, group_name="sock_ws2_32_WSA",
    weight=V_WEIGHT_CRITICAL
)

hook_WSARecvFrom = ApiHookCustom(
    "ws2_32.dll", "WSARecvFrom", handler_api_invoke=handler_WSARecvFrom, group_name="sock_ws2_32_WSA",
    weight=V_WEIGHT_CRITICAL
)

hook_WSARecvDisconnect = ApiHookLogParams(
    "ws2_32.dll", "WSARecvDisconnect", group_name="sock_ws2_32_WSA", weight=V_WEIGHT_LOW
)


# ---------------------------------------------------------------------------
# HTTP - wininet.dll


hook_InternetOpenA = ApiHookLogParams(
    "wininet.dll", "InternetOpenA", group_name="http_wininet", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "agent", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "proxy_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x10, "proxy_pwd", V_PARAM_LOG_PASTR)
    ],
    cstk_filter_depth=2
)

hook_InternetConnectA = ApiHookCustom(
    "wininet.dll", "InternetConnectA", handler_api_invoke=handler_InternetConnectA, group_name="http_wininet",
    weight=V_WEIGHT_CRITICAL
)

hook_InternetCrackUrlA = ApiHookLogParams(
    "wininet.dll", "InternetCrackUrlA", group_name="http_wininet", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR)],
    cstk_filter_depth=2
)

hook_InternetOpenUrlA = ApiHookLogParams(
    "wininet.dll", "InternetOpenUrlA", group_name="http_wininet", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "url", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "headers", V_PARAM_LOG_PASTR)
    ],
    cstk_filter_depth=2
)

hook_InternetReadFile = ApiHookLogParams(
    "wininet.dll", "InternetReadFile", group_name="http_wininet", weight=V_WEIGHT_CRITICAL
)

hook_InternetReadFileExA = ApiHookLogParams(
    "wininet.dll", "InternetReadFileExA", group_name="http_wininet", weight=V_WEIGHT_CRITICAL,
    cstk_filter_depth=2
)

hook_InternetWriteFile = ApiHookLogParams(
    "wininet.dll", "InternetWriteFile", group_name="http_wininet", weight=V_WEIGHT_IGNORE
)

hook_HttpOpenRequestA = ApiHookLogParams(
    "wininet.dll", "HttpOpenRequestA", group_name="http_wininet", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "verb", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "obj", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x10, "ver", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x14, "refer", V_PARAM_LOG_PASTR)
    ]
)

hook_HttpOpenRequestW = ApiHookLogParams(
    "wininet.dll", "HttpOpenRequestW", group_name="http_wininet", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "verb", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "obj", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "ver", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x14, "refer", V_PARAM_LOG_PUSTR)
    ]
)

hook_HttpSendRequestA = ApiHookLogParams(
    "wininet.dll", "HttpSendRequestA", group_name="http_wininet", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "headers", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x10, "opt", V_PARAM_LOG_PASTR)
    ]
)

hook_HttpSendRequestW = ApiHookLogParams(
    "wininet.dll", "HttpSendRequestW", group_name="http_wininet", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "headers", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "opt", V_PARAM_LOG_PUSTR)
    ]
)

hook_HttpSendRequestExA = ApiHookCustom(
    "wininet.dll", "HttpSendRequestExA", handler_api_invoke=handler_HttpSendRequestExA, group_name="http_wininet",
    weight=V_WEIGHT_CRITICAL
)

hook_HttpSendRequestExW = ApiHookCustom(
    "wininet.dll", "HttpSendRequestExW", handler_api_invoke=handler_HttpSendRequestExW, group_name="http_wininet",
    weight=V_WEIGHT_CRITICAL
)

hook_HttpAddRequestHeadersA = ApiHookLogParams(
    "wininet.dll", "HttpAddRequestHeadersA", group_name="http_wininet", weight=V_WEIGHT_HIGH,
    cstk_filter_depth=2
)

hook_ = ApiHookLogParams(
    "wininet.dll", "", group_name="http_wininet", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    is_fragile=True
)

hook_InternetFindNextFileA = ApiHookLogParams(
    "wininet.dll", "InternetFindNextFileA", group_name="http_wininet", weight=V_WEIGHT_IGNORE,
    cstk_filter_depth=2, is_fragile=True
)

hook_InternetGetCookieExW = ApiHookLogParams(
    "wininet.dll", "InternetGetCookieExW", group_name="http_wininet", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "coockie", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=3, is_fragile=True
)

hook_InternetSetCookieA = ApiHookLogParams(
    "wininet.dll", "InternetSetCookieA", group_name="http_wininet", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR),
        ParamLogCtrl(8, "coockie_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "coockie_data", V_PARAM_LOG_PASTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_InternetSetCookieExA = ApiHookLogParams(
    "wininet.dll", "InternetSetCookieExA", group_name="http_wininet", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR),
        ParamLogCtrl(8, "coockie_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "coockie_data", V_PARAM_LOG_PASTR)
    ],
    is_fragile=True
)

hook_InternetSetCookieExW = ApiHookLogParams(
    "wininet.dll", "InternetSetCookieExW", group_name="http_wininet", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "coockie_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "coockie_data", V_PARAM_LOG_PUSTR)
    ],
    is_fragile=True
)

hook_InternetAttemptConnect = ApiHookLogParams(
    "wininet.dll", "InternetAttemptConnect", group_name="http_wininet", weight=V_WEIGHT_IGNORE,
    is_fragile=True
)

hook_InternetCanonicalizeUrlA = ApiHookLogParams(
    "wininet.dll", "InternetCanonicalizeUrlA", group_name="http_wininet", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_InternetCanonicalizeUrlW = ApiHookLogParams(
    "wininet.dll", "InternetCanonicalizeUrlW", group_name="http_wininet", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_DeleteUrlCacheEntryA = ApiHookLogParams(
    "wininet.dll", "DeleteUrlCacheEntryA", group_name="http_wininet", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR)],
    cstk_filter_depth=2, is_fragile=True
)


# ---------------------------------------------------------------------------
# HTTP - winhttp.dll


hook_WinHttpOpen = ApiHookLogParams(
    "winhttp.dll", "WinHttpOpen", group_name="http_winhttp", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "agent", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "proxy_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "proxy_pwd", V_PARAM_LOG_PUSTR)
    ]
)

hook_WinHttpCloseHandle = ApiHookLogParams(
    "winhttp.dll", "WinHttpCloseHandle", group_name="http_winhttp", weight=V_WEIGHT_IGNORE
)

hook_WinHttpConnect = ApiHookLogParams(
    "winhttp.dll", "WinHttpConnect", group_name="http_winhttp", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "svr_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "svr_port", V_PARAM_LOG_INT)
    ]
)

hook_WinHttpOpenRequest = ApiHookLogParams(
    "winhttp.dll", "WinHttpOpenRequest", group_name="http_winhttp", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "verb", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "obj", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "ver", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x14, "refer", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x18, "acept_type", V_PARAM_LOG_PPUSTR)
    ]
)

hook_WinHttpSendRequest = ApiHookLogParams(
    "winhttp.dll", "WinHttpSendRequest", group_name="http_winhttp", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[ParamLogCtrl(8, "headers", V_PARAM_LOG_PUSTR)]
)

hook_WinHttpReceiveResponse = ApiHookLogParams(
    "winhttp.dll", "WinHttpReceiveResponse", group_name="http_winhttp", weight=V_WEIGHT_LOW
)

hook_WinHttpQueryHeaders = ApiHookLogParams(
    "winhttp.dll", "WinHttpQueryHeaders", group_name="http_winhttp", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(0xC, "name", V_PARAM_LOG_PUSTR)]
)

hook_WinHttpQueryDataAvailable = ApiHookLogParams(
    "winhttp.dll", "WinHttpQueryDataAvailable", group_name="http_winhttp", weight=V_WEIGHT_IGNORE,
)

hook_WinHttpReadData = ApiHookLogParams(
    "winhttp.dll", "WinHttpReadData", group_name="http_winhttp", weight=V_WEIGHT_CRITICAL
)

hook_WinHttpAddRequestHeaders = ApiHookLogParams(
    "winhttp.dll", "WinHttpAddRequestHeaders", group_name="http_winhttp", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[ParamLogCtrl(8, "headers", V_PARAM_LOG_PUSTR)]
)

hook_WinHttpCrackUrl = ApiHookLogParams(
    "winhttp.dll", "WinHttpCrackUrl", group_name="http_winhttp", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR)]
)

hook_WinHttpCreateUrl = ApiHookCustom(
    "winhttp.dll", "WinHttpCreateUrl", handler_api_invoke=handler_WinHttpCreateUrl, group_name="http_winhttp",
    weight=V_WEIGHT_LOW
)

hook_WinHttpWriteData = ApiHookCustom(
    "winhttp.dll", "WinHttpWriteData", handler_api_invoke=handler_WinHttpWriteData, group_name="http_winhttp",
    weight=V_WEIGHT_LOW
)


# ---------------------------------------------------------------------------
# HTTP - urlmon.dll


hook_URLDownloadW = ApiHookLogParams(
    "urlmon.dll", "URLDownloadW", group_name="http_urlmon", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "url", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2
)

hook_URLDownloadToFileW = ApiHookLogParams(
    "urlmon.dll", "URLDownloadToFileW", group_name="http_urlmon", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "url", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2
)

hook_URLDownloadToCacheFileW = ApiHookLogParams(
    "urlmon.dll", "URLDownloadToCacheFileW", group_name="http_urlmon", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "url", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2
)


# ---------------------------------------------------------------------------
# HTTP - rasapi32.dll


hook_RasGetConnectStatusW = ApiHookLogParams(
    "rasapi32.dll", "RasGetConnectStatusW", group_name="http_rasapi32", weight=V_WEIGHT_LOW,
    cstk_filter_depth=2
)


# ---------------------------------------------------------------------------
# 进程 - kernel32.dll


hook_IsWow64Process = ApiHookCustom(
    "kernel32.dll", "IsWow64Process", handler_api_invoke=handler_IsWow64Process, group_name="proc_kernel32",
    weight=V_WEIGHT_HIGH
)

hook_CreateProcessInternalW = ApiHookCustom(
    "kernel32.dll", "CreateProcessInternalW", handler_api_invoke=handler_CreateProcessInternalW, group_name="proc_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=3
)

hook_CreateRemoteThread = ApiHookCustom(
    "kernel32.dll", "CreateRemoteThread", handler_api_invoke=handler_CreateRemoteThread, group_name="proc_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=2
)

hook_OpenProcess = ApiHookCustom(
    "kernel32.dll", "OpenProcess", handler_api_invoke=handler_OpenProcess, group_name="proc_kernel32",
    weight=V_WEIGHT_HIGH
)

hook_GetExitCodeProcess = ApiHookCustom(
    "kernel32.dll", "GetExitCodeProcess", handler_api_invoke=handler_GetExitCodeProcess, group_name="proc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_OpenThread = ApiHookLogParams(
    "kernel32.dll", "OpenThread", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "tid", V_PARAM_LOG_INT)]
)

hook_TerminateThread = ApiHookLogParams(
    "kernel32.dll", "TerminateThread", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "code", V_PARAM_LOG_INT)]
)

hook_SuspendThread = ApiHookLogParams(
    "kernel32.dll", "SuspendThread", group_name="proc_kernel32", weight=V_WEIGHT_LOW
)

hook_ResumeThread = ApiHookLogParams(
    "kernel32.dll", "ResumeThread", group_name="proc_kernel32", weight=V_WEIGHT_CRITICAL
)

hook_ExitThread = ApiHookLogParams(
    "kernel32.dll", "ExitThread", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "code", V_PARAM_LOG_INT)]
)

hook_SetThreadContext = ApiHookCustom(
    "kernel32.dll", "SetThreadContext", handler_api_invoke=handler_SetThreadContext, group_name="proc_kernel32",
    weight=V_WEIGHT_CRITICAL, is_fragile=True
)

hook_GetThreadContext = ApiHookCustom(
    "kernel32.dll", "GetThreadContext", handler_api_invoke=handler_GetThreadContext, group_name="proc_kernel32",
    weight=V_WEIGHT_HIGH, is_fragile=True
)

hook_ReadProcessMemory = ApiHookCustom(
    "kernel32.dll", "ReadProcessMemory", handler_api_invoke=handler_ReadProcessMemory, group_name="proc_kernel32",
    weight=V_WEIGHT_HIGH, cstk_filter_depth=2, is_fragile=True
)

hook_WriteProcessMemory = ApiHookCustom(
    "kernel32.dll", "WriteProcessMemory", handler_api_invoke=handler_WriteProcessMemory, group_name="proc_kernel32",
    weight=V_WEIGHT_CRITICAL, is_fragile=True
)

hook_CreateToolhelp32Snapshot = ApiHookCustom(
    "kernel32.dll", "CreateToolhelp32Snapshot", handler_api_invoke=handler_CreateToolhelp32Snapshot, group_name="proc_kernel32",
    weight=V_WEIGHT_HIGH, is_fragile=True
)

hook_Process32FirstW = ApiHookLogParams(
    "kernel32.dll", "Process32FirstW", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    cstk_filter_depth=2, is_fragile=True
)

hook_Process32NextW = ApiHookLogParams(
    "kernel32.dll", "Process32NextW", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    cstk_filter_depth=2, max_invoke_cnt_runtime=10, is_fragile=True
)

hook_Module32FirstW = ApiHookLogParams(
    "kernel32.dll", "Module32FirstW", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    cstk_filter_depth=2, is_fragile=True
)

hook_Module32NextW = ApiHookLogParams(
    "kernel32.dll", "Module32NextW", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    cstk_filter_depth=2, max_invoke_cnt_runtime=10, is_fragile=True
)

hook_Thread32First = ApiHookLogParams(
    "kernel32.dll", "Thread32First", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_Thread32Next = ApiHookLogParams(
    "kernel32.dll", "Thread32Next", group_name="proc_kernel32", weight=V_WEIGHT_MIDDLE,
    max_invoke_cnt_runtime=10, is_fragile=True
)


# ---------------------------------------------------------------------------
# 文件 - kernel32.dll


hook_CreateFileMappingW = ApiHookCustom(
    "kernel32.dll", "CreateFileMappingW", handler_api_invoke=handler_CreateFileMappingW, group_name="file_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_OpenFileMappingW = ApiHookLogParams(
    "kernel32.dll", "OpenFileMappingW", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_MapViewOfFileEx = ApiHookLogParams(
    "kernel32.dll", "MapViewOfFileEx", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE
)

hook_UnmapViewOfFile = ApiHookCustom(
    "kernel32.dll", "UnmapViewOfFile", handler_api_invoke=handler_UnmapViewOfFile, group_name="file_kernel32",
    weight=V_WEIGHT_LOW
)

hook_CreateFileW = ApiHookCustom(
    "kernel32.dll", "CreateFileW", handler_api_invoke=handler_CreateFileW, group_name="file_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=3, is_too_frequent=True
)

hook_ReadFile = ApiHookLogParams(
    "kernel32.dll", "ReadFile", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE,
    cstk_filter_depth=2, is_too_frequent=True
)

hook_ReadFileEx = ApiHookLogParams(
    "kernel32.dll", "ReadFileEx", group_name="file_kernel32", weight=V_WEIGHT_LOW
)

hook_WriteFile = ApiHookCustom(
    "kernel32.dll", "WriteFile", handler_api_invoke=handler_WriteFile, group_name="file_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=2
)

hook_WriteFileEx = ApiHookCustom(
    "kernel32.dll", "WriteFileEx", handler_api_invoke=handler_WriteFileEx, group_name="file_kernel32",
    weight=V_WEIGHT_CRITICAL
)

hook_CopyFileExW = ApiHookLogParams(
    "kernel32.dll", "CopyFileExW", group_name="file_kernel32", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "file_old", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "file_new", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2
)

hook_MoveFileWithProgressW = ApiHookCustom(
    "kernel32.dll", "MoveFileWithProgressW", handler_api_invoke=handler_MoveFileWithProgressW, group_name="file_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=3
)

hook_CreateDirectoryW = ApiHookLogParams(
    "kernel32.dll", "CreateDirectoryW", group_name="file_kernel32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(4, "dir", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2
)

hook_CreateDirectoryExW = ApiHookLogParams(
    "kernel32.dll", "CreateDirectoryExW", group_name="file_kernel32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "dir_template", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "dir_new", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2
)

hook_RemoveDirectoryW = ApiHookCustom(
    "kernel32.dll", "RemoveDirectoryW", handler_api_invoke=handler_RemoveDirectoryW, group_name="file_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=2
)

hook_ReplaceFileW = ApiHookCustom(
    "kernel32.dll", "ReplaceFileW", handler_api_invoke=handler_ReplaceFileW, group_name="file_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=2
)

hook_DeleteFileW = ApiHookCustom(
    "kernel32.dll", "DeleteFileW", handler_api_invoke=handler_DeleteFileW, group_name="file_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=2
)

hook_DeviceIoControl = ApiHookLogParams(
    "kernel32.dll", "DeviceIoControl", group_name="file_kernel32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "code", V_PARAM_LOG_INT)],
)

hook_FindFirstFileExW = ApiHookLogParams(
    "kernel32.dll", "FindFirstFileExW", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2
)

hook_FindNextFileW = ApiHookLogParams(
    "kernel32.dll", "FindNextFileW", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE,
    cstk_filter_depth=2, max_invoke_cnt_runtime=10, is_fragile=True
)

hook_SetFileAttributesW = ApiHookCustom(
    "kernel32.dll", "SetFileAttributesW", handler_api_invoke=handler_SetFileAttributesW, group_name="file_kernel32",
    weight=V_WEIGHT_HIGH, cstk_filter_depth=2
)

hook_SetFileTime = ApiHookCustom(
    "kernel32.dll", "SetFileTime", handler_api_invoke=handler_SetFileTime, group_name="file_kernel32",
    weight=V_WEIGHT_HIGH
)

hook_GetFileTime = ApiHookLogParams(
    "kernel32.dll", "GetFileTime", group_name="file_kernel32", weight=V_WEIGHT_IGNORE
)

hook_GetFileSizeEx = ApiHookLogParams(
    "kernel32.dll", "GetFileSizeEx", group_name="file_kernel32", weight=V_WEIGHT_IGNORE,
    cstk_filter_depth=2
)

hook_GetTempPathW = ApiHookCustom(
    "kernel32.dll", "GetTempPathW", handler_api_invoke=handler_GetTempPathW, group_name="file_kernel32",
    weight=V_WEIGHT_LOW, cstk_filter_depth=2
)

hook_GetTempFileNameW = ApiHookCustom(
    "kernel32.dll", "GetTempFileNameW", handler_api_invoke=handler_GetTempFileNameW, group_name="file_kernel32",
    weight=V_WEIGHT_LOW, cstk_filter_depth=2
)

hook_GetSystemDirectoryA = ApiHookCustom(
    "kernel32.dll", "GetSystemDirectoryA", handler_api_invoke=handler_GetSystemDirectoryA, group_name="file_kernel32",
    weight=V_WEIGHT_LOW
)

hook_GetSystemDirectoryW = ApiHookCustom(
    "kernel32.dll", "GetSystemDirectoryW", handler_api_invoke=handler_GetSystemDirectoryW, group_name="file_kernel32",
    weight=V_WEIGHT_LOW
)

hook_GetDiskFreeSpaceW = ApiHookLogParams(
    "kernel32.dll", "GetDiskFreeSpaceW", group_name="file_kernel32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_GetDiskFreeSpaceExW = ApiHookLogParams(
    "kernel32.dll", "GetDiskFreeSpaceExW", group_name="file_kernel32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_GetDriveTypeW = ApiHookLogParams(
    "kernel32.dll", "GetDriveTypeW", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_GetVolumeInformationW = ApiHookLogParams(
    "kernel32.dll", "GetVolumeInformationW", group_name="file_kernel32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_GetVolumeNameForVolumeMountPointW = ApiHookLogParams(
    "kernel32.dll", "GetVolumeNameForVolumeMountPointW", group_name="file_kernel32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_FindFirstVolumeW = ApiHookLogParams(
    "kernel32.dll", "FindFirstVolumeW", group_name="file_kernel32", weight=V_WEIGHT_HIGH,
    cstk_filter_depth=2, is_fragile=True
)

hook_FindNextVolumeW = ApiHookLogParams(
    "kernel32.dll", "FindNextVolumeW", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE,
    cstk_filter_depth=2, is_fragile=True
)

hook_GetFullPathNameW = ApiHookCustom(
    "kernel32.dll", "GetFullPathNameW", handler_api_invoke=handler_GetFullPathNameW, group_name="file_kernel32",
    weight=V_WEIGHT_LOW, cstk_filter_depth=3, is_fragile=True
)

hook_GetVolumePathNamesForVolumeNameW = ApiHookLogParams(
    "kernel32.dll", "GetVolumePathNamesForVolumeNameW", group_name="file_kernel32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_GetLogicalDriveStringsA = ApiHookLogParams(
    "kernel32.dll", "GetLogicalDriveStringsA", group_name="file_kernel32", weight=V_WEIGHT_IGNORE,
    is_fragile=True
)

hook_GetLogicalDriveStringsW = ApiHookLogParams(
    "kernel32.dll", "GetLogicalDriveStringsW", group_name="file_kernel32", weight=V_WEIGHT_IGNORE,
    is_fragile=True
)

hook_GetLogicalDrives = ApiHookLogParams(
    "kernel32.dll", "GetLogicalDrives", group_name="file_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SetDllDirectoryA = ApiHookLogParams(
    "kernel32.dll", "SetDllDirectoryA", group_name="file_kernel32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "dir", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_SetDllDirectoryW = ApiHookLogParams(
    "kernel32.dll", "SetDllDirectoryW", group_name="file_kernel32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "dir", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 文件 - shlwapi.dll


hook_PathFileExistsA = ApiHookLogParams(
    "shlwapi.dll", "PathFileExistsA", group_name="file_shlwapi", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PASTR)]
)

hook_PathFileExistsW = ApiHookLogParams(
    "shlwapi.dll", "PathFileExistsW", group_name="file_shlwapi", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)]
)

hook_PathRemoveFileSpecA = ApiHookLogParams(
    "shlwapi.dll", "PathRemoveFileSpecA", group_name="file_shlwapi", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PASTR)]
)

hook_PathRemoveFileSpecW = ApiHookLogParams(
    "shlwapi.dll", "PathRemoveFileSpecW", group_name="file_shlwapi", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)]
)


# ---------------------------------------------------------------------------
# 服务 - advapi32.dll


hook_OpenSCManagerA = ApiHookLogParams(
    "advapi32.dll", "OpenSCManagerA", group_name="svc_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(4, "machine", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "database", V_PARAM_LOG_PASTR)]
)

hook_OpenSCManagerW = ApiHookLogParams(
    "advapi32.dll", "OpenSCManagerW", group_name="svc_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(4, "machine", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "database", V_PARAM_LOG_PUSTR)]
)

hook_CreateServiceA = ApiHookCustom(
    "advapi32.dll", "CreateServiceA", handler_api_invoke=handler_CreateServiceA, group_name="svc_advapi32",
    weight=V_WEIGHT_CRITICAL
)

hook_CreateServiceW = ApiHookCustom(
    "advapi32.dll", "CreateServiceW", handler_api_invoke=handler_CreateServiceW, group_name="svc_advapi32",
    weight=V_WEIGHT_CRITICAL
)

hook_ControlService = ApiHookCustom(
    "advapi32.dll", "ControlService", handler_api_invoke=handler_ControlService, group_name="svc_advapi32",
    weight=V_WEIGHT_HIGH
)

hook_DeleteService = ApiHookLogParams(
    "advapi32.dll", "DeleteService", group_name="svc_advapi32", weight=V_WEIGHT_CRITICAL
)

hook_GetServiceDisplayNameA = ApiHookLogParams(
    "advapi32.dll", "GetServiceDisplayNameA", group_name="svc_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "svc", V_PARAM_LOG_PASTR)]
)

hook_GetServiceDisplayNameW = ApiHookLogParams(
    "advapi32.dll", "GetServiceDisplayNameW", group_name="svc_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "svc", V_PARAM_LOG_PUSTR)]
)

hook_GetServiceKeyNameA = ApiHookLogParams(
    "advapi32.dll", "GetServiceKeyNameA", group_name="svc_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "display_name", V_PARAM_LOG_PASTR)]
)

hook_GetServiceKeyNameW = ApiHookLogParams(
    "advapi32.dll", "GetServiceKeyNameW", group_name="svc_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "display_name", V_PARAM_LOG_PUSTR)]
)

hook_OpenServiceA = ApiHookLogParams(
    "advapi32.dll", "OpenServiceA", group_name="svc_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(8, "svc", V_PARAM_LOG_PASTR)]
)

hook_OpenServiceW = ApiHookLogParams(
    "advapi32.dll", "OpenServiceW", group_name="svc_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(8, "svc", V_PARAM_LOG_PUSTR)]
)

hook_RegisterServiceCtrlHandlerW = ApiHookLogParams(
    "advapi32.dll", "RegisterServiceCtrlHandlerW", group_name="svc_advapi32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[ParamLogCtrl(4, "svc", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)],
    cstk_filter_depth=2
)

hook_RegisterServiceCtrlHandlerExW = ApiHookLogParams(
    "advapi32.dll", "RegisterServiceCtrlHandlerExW", group_name="svc_advapi32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "svc", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)],
    cstk_filter_depth=2
)

hook_StartServiceA = ApiHookLogParams(
    "advapi32.dll", "StartServiceA", group_name="svc_advapi32", weight=V_WEIGHT_CRITICAL
)

hook_StartServiceW = ApiHookLogParams(
    "advapi32.dll", "StartServiceW", group_name="svc_advapi32", weight=V_WEIGHT_CRITICAL
)

hook_StartServiceCtrlDispatcherA = ApiHookCustom(
    "advapi32.dll", "StartServiceCtrlDispatcherA", handler_api_invoke=handler_StartServiceCtrlDispatcherA, group_name="svc_advapi32",
    weight=V_WEIGHT_LOW
)

hook_StartServiceCtrlDispatcherW = ApiHookCustom(
    "advapi32.dll", "StartServiceCtrlDispatcherW", handler_api_invoke=handler_StartServiceCtrlDispatcherW, group_name="svc_advapi32",
    weight=V_WEIGHT_LOW
)


# ---------------------------------------------------------------------------
# 加密(crypto) - advapi32.dll


hook_CryptAcquireContextA = ApiHookLogParams(
    "advapi32.dll", "CryptAcquireContextA", group_name="crypto_advapi32", weight=V_WEIGHT_CRITICAL,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "container", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "provider", V_PARAM_LOG_PASTR)
    ],
    cstk_filter_depth=2
)

hook_CryptReleaseContext = ApiHookLogParams(
    "advapi32.dll", "CryptReleaseContext", group_name="crypto_advapi32", weight=V_WEIGHT_MIDDLE
)

hook_CryptSetProvParam = ApiHookLogParams(
    "advapi32.dll", "CryptSetProvParam", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptGetProvParam = ApiHookLogParams(
    "advapi32.dll", "CryptGetProvParam", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptCreateHash = ApiHookLogParams(
    "advapi32.dll", "CryptCreateHash", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptHashData = ApiHookLogParams(
    "advapi32.dll", "CryptHashData", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptGetHashParam = ApiHookLogParams(
    "advapi32.dll", "CryptGetHashParam", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptSetHashParam = ApiHookLogParams(
    "advapi32.dll", "CryptSetHashParam", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptHashSessionKey = ApiHookLogParams(
    "advapi32.dll", "CryptHashSessionKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptDestroyHash = ApiHookLogParams(
    "advapi32.dll", "CryptDestroyHash", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptGenRandom = ApiHookLogParams(
    "advapi32.dll", "CryptGenRandom", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptDeriveKey = ApiHookLogParams(
    "advapi32.dll", "CryptDeriveKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptGenKey = ApiHookLogParams(
    "advapi32.dll", "CryptGenKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptDestroyKey = ApiHookLogParams(
    "advapi32.dll", "CryptDestroyKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptImportKey = ApiHookLogParams(
    "advapi32.dll", "CryptImportKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptExportKey = ApiHookLogParams(
    "advapi32.dll", "CryptExportKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptGetKeyParam = ApiHookLogParams(
    "advapi32.dll", "CryptGetKeyParam", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptSetKeyParam = ApiHookLogParams(
    "advapi32.dll", "CryptSetKeyParam", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptGetUserKey = ApiHookLogParams(
    "advapi32.dll", "CryptGetUserKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptSignHashA = ApiHookLogParams(
    "advapi32.dll", "CryptSignHashA", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptSignHashW = ApiHookLogParams(
    "advapi32.dll", "CryptSignHashW", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptVerifySignatureA = ApiHookLogParams(
    "advapi32.dll", "CryptVerifySignatureA", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptVerifySignatureW = ApiHookLogParams(
    "advapi32.dll", "CryptVerifySignatureW", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptEncrypt = ApiHookLogParams(
    "advapi32.dll", "CryptEncrypt", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptDecrypt = ApiHookLogParams(
    "advapi32.dll", "CryptDecrypt", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptDuplicateHash = ApiHookLogParams(
    "advapi32.dll", "CryptDuplicateHash", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)

hook_CryptDuplicateKey = ApiHookLogParams(
    "advapi32.dll", "CryptDuplicateKey", group_name="crypto_advapi32", weight=V_WEIGHT_IGNORE
)


# ---------------------------------------------------------------------------
# 字符串 - kernel32.dll


# ApiHookLogParams("kernel32.dll", "lstrcatA", [ParamLogCtrl(4, "str1", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "str2", V_PARAM_LOG_PASTR)]),
# ApiHookLogParams("kernel32.dll", "lstrcatW", [ParamLogCtrl(4, "str1", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "str2", V_PARAM_LOG_PUSTR)]),
# ApiHookCustom("kernel32.dll", "lstrcmpA", handler=handler_lstrcmpA),
# ApiHookCustom("kernel32.dll", "lstrcmpW", handler=handler_lstrcmpW),
# ApiHookCustom("kernel32.dll", "lstrcmpiA", handler=handler_lstrcmpiA),
# ApiHookCustom("kernel32.dll", "lstrcmpiW", handler=handler_lstrcmpiW),
# ApiHookLogParams("kernel32.dll", "lstrcpyA", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PASTR)]),
# ApiHookLogParams("kernel32.dll", "lstrcpyW", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PUSTR)]),
# ApiHookLogParams("kernel32.dll", "lstrcpynA", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "len", V_PARAM_LOG_INT)]),
# ApiHookLogParams("kernel32.dll", "lstrcpynW", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "len", V_PARAM_LOG_INT)]),
# ApiHookLogParams("kernel32.dll", "lstrlenA", [ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)]),
# ApiHookLogParams("kernel32.dll", "lstrlenW", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),


# ---------------------------------------------------------------------------
# 字符串 - shalwapi.dll


# # todo: there are 2 deeper functions: wvnsprintfA/W
# ApiHookCustom("shlwapi.dll", "wnsprintfA", handler=handler_wnsprintfA, cstk_filter_depth=2),
# ApiHookCustom("shlwapi.dll", "wnsprintfW", handler=handler_wnsprintfW, cstk_filter_depth=2),


# ---------------------------------------------------------------------------
# 字符串 - ntdll.dll

# # bp at these apis will result in unknow results...
# ApiHookLogParams("ntdll.dll", "RtlInitString", [ParamLogCtrl(8, "str", V_PARAM_LOG_PASTR)]),
# ApiHookLogParams("ntdll.dll", "RtlInitAnsiString", [ParamLogCtrl(8, "str", V_PARAM_LOG_PASTR)]),
# ApiHookLogParams("ntdll.dll", "RtlInitUnicodeString", [ParamLogCtrl(8, "str", V_PARAM_LOG_PUSTR)]),
# ApiHookLogParams("ntdll.dll", "RtlInitUnicodeStringEx", [ParamLogCtrl(8, "str", V_PARAM_LOG_PUSTR)]),
# ApiHookLogParams("ntdll.dll", "RtlIsDosDeviceName_U", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
# ApiHookLogParams("ntdll.dll", "RtlDosPathNameToNtPathName_U", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
# ApiHookLogParams("ntdll.dll", "RtlDetermineDosPathNameType_U"),


# ---------------------------------------------------------------------------
# 窗口 - user32.dll


hook_ = ApiHookLogParams(
    "user32.dll", "FindWindowA", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "class_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(8, "win_name", V_PARAM_LOG_PASTR)
    ]
)

hook_FindWindowW = ApiHookLogParams(
    "user32.dll", "FindWindowW", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "class_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "win_name", V_PARAM_LOG_PUSTR)
    ]
)

hook_FindWindowExA = ApiHookLogParams(
    "user32.dll", "FindWindowExA", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(0xC, "class_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x10, "win_name", V_PARAM_LOG_PASTR)
    ]
)

hook_FindWindowExW = ApiHookLogParams(
    "user32.dll", "FindWindowExW", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(0xC, "class_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "win_name", V_PARAM_LOG_PUSTR)
    ]
)

hook_GetDesktopWindow = ApiHookLogParams(
    "user32.dll", "GetDesktopWindow", group_name="win_user32", weight=V_WEIGHT_IGNORE
)

hook_DialogBoxParamA = ApiHookLogParams(
    "user32.dll", "DialogBoxParamA", group_name="win_user32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "template", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x10, "cbk", V_PARAM_LOG_INT)
    ]
)

hook_DialogBoxParamW = ApiHookLogParams(
    "user32.dll", "DialogBoxParamW", group_name="win_user32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "template", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "cbk", V_PARAM_LOG_INT)
    ]
)

hook_MessageBoxTimeoutW = ApiHookLogParams(
    "user32.dll", "MessageBoxTimeoutW", group_name="win_user32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "txt", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "caption", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x18, "mescs", V_PARAM_LOG_INT)
    ],
    cstk_filter_depth=4
)

hook_MessageBoxIndirectA = ApiHookCustom(
    "user32.dll", "MessageBoxIndirectA", handler_api_invoke=handler_MessageBoxIndirectA, group_name="win_user32",
    weight=V_WEIGHT_LOW
)

hook_MessageBoxIndirectW = ApiHookCustom(
    "user32.dll", "MessageBoxIndirectW", handler_api_invoke=handler_MessageBoxIndirectW, group_name="win_user32",
    weight=V_WEIGHT_LOW
)

hook_RegisterClassA = ApiHookCustom(
    "user32.dll", "RegisterClassA", handler_api_invoke=handler_RegisterClassA, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_RegisterClassW = ApiHookCustom(
    "user32.dll", "RegisterClassW", handler_api_invoke=handler_RegisterClassW, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_RegisterClassExA = ApiHookCustom(
    "user32.dll", "RegisterClassExA", handler_api_invoke=handler_RegisterClassExA, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_RegisterClassExW = ApiHookCustom(
    "user32.dll", "RegisterClassExW", handler_api_invoke=handler_RegisterClassExW, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_PostQuitMessage = ApiHookLogParams(
    "user32.dll", "PostQuitMessage", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "code", V_PARAM_LOG_INT)]
)

hook_CreateWindowExA = ApiHookLogParams(
    "user32.dll", "CreateWindowExA", group_name="win_user32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "class", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "win", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x14, "x", V_PARAM_LOG_INT),
        ParamLogCtrl(0x18, "y", V_PARAM_LOG_INT),
        ParamLogCtrl(0x1C, "width", V_PARAM_LOG_INT),
        ParamLogCtrl(0x20, "height", V_PARAM_LOG_INT)
    ],
    is_fragile=True
)

hook_ = ApiHookLogParams(
    "user32.dll", "", group_name="win_user32", weight=V_WEIGHT_HIGH,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "class", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x14, "x", V_PARAM_LOG_INT),
        ParamLogCtrl(0x18, "y", V_PARAM_LOG_INT),
        ParamLogCtrl(0x1C, "width", V_PARAM_LOG_INT),
        ParamLogCtrl(0x20, "height", V_PARAM_LOG_INT)
    ],
    is_fragile=True
)

hook_EnumWindows = ApiHookLogParams(
    "user32.dll", "EnumWindows", group_name="win_user32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(4, "cbk", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_EnumChildWindows = ApiHookLogParams(
    "user32.dll", "EnumChildWindows", group_name="win_user32", weight=V_WEIGHT_LOW,
    param_log_ctrl_list=[ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_EnumDesktopWindows = ApiHookLogParams(
    "user32.dll", "EnumDesktopWindows", group_name="win_user32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_EnumDesktopsA = ApiHookLogParams(
    "user32.dll", "EnumDesktopsA", group_name="win_user32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_EnumDesktopsW = ApiHookLogParams(
    "user32.dll", "EnumDesktopsW", group_name="win_user32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_EnumDisplayDevicesA = ApiHookLogParams(
    "user32.dll", "EnumDisplayDevicesA", group_name="win_user32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "file", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_EnumDisplayDevicesW = ApiHookLogParams(
    "user32.dll", "EnumDisplayDevicesW", group_name="win_user32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_CreateWindowStationA = ApiHookLogParams(
    "user32.dll", "CreateWindowStationA", group_name="win_user32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "win", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_CreateWindowStationW = ApiHookLogParams(
    "user32.dll", "CreateWindowStationW", group_name="win_user32", weight=V_WEIGHT_IGNORE,
    param_log_ctrl_list=[ParamLogCtrl(4, "win", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_DispatchMessageA = ApiHookCustom(
    "user32.dll", "DispatchMessageA", handler_api_invoke=handler_DispatchMessageA, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_DispatchMessageW = ApiHookCustom(
    "user32.dll", "DispatchMessageW", handler_api_invoke=handler_DispatchMessageW, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_PeekMessageA = ApiHookLogParams(
    "user32.dll", "PeekMessageA", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_PeekMessageW = ApiHookLogParams(
    "user32.dll", "PeekMessageW", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_PostMessageA = ApiHookCustom(
    "user32.dll", "PostMessageA", handler_api_invoke=handler_PostMessageA, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_PostMessageW = ApiHookCustom(
    "user32.dll", "PostMessageW", handler_api_invoke=handler_PostMessageW, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_SendMessageA = ApiHookCustom(
    "user32.dll", "SendMessageA", handler_api_invoke=handler_SendMessageA, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_SendMessageW = ApiHookCustom(
    "user32.dll", "SendMessageW", handler_api_invoke=handler_SendMessageW, group_name="win_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_RegisterServicesProcess = ApiHookLogParams(
    "user32.dll", "RegisterServicesProcess", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "pid", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_SetProcessWindowStation = ApiHookLogParams(
    "user32.dll", "SetProcessWindowStation", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_OpenDesktopA = ApiHookLogParams(
    "user32.dll", "OpenDesktopA", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "desktop", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_OpenDesktopW = ApiHookLogParams(
    "user32.dll", "OpenDesktopW", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "desktop", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_SetThreadDesktop = ApiHookLogParams(
    "user32.dll", "SetThreadDesktop", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_OpenWindowStationA = ApiHookLogParams(
    "user32.dll", "OpenWindowStationA", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "station", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_OpenWindowStationW = ApiHookLogParams(
    "user32.dll", "OpenWindowStationW", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "station", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_EmptyClipboard = ApiHookLogParams(
    "user32.dll", "EmptyClipboard", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetClipboardData = ApiHookLogParams(
    "user32.dll", "GetClipboardData", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_OpenClipboard = ApiHookLogParams(
    "user32.dll", "OpenClipboard", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SetClipboardData = ApiHookLogParams(
    "user32.dll", "SetClipboardData", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetKeyboardState = ApiHookLogParams(
    "user32.dll", "GetKeyboardState", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SetKeyboardState = ApiHookLogParams(
    "user32.dll", "SetKeyboardState", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetAsyncKeyState = ApiHookLogParams(
    "user32.dll", "GetAsyncKeyState", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetKeyState = ApiHookLogParams(
    "user32.dll", "GetKeyState", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_keybd_event = ApiHookLogParams(
    "user32.dll", "keybd_event", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_mouse_event = ApiHookLogParams(
    "user32.dll", "mouse_event", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetCursorPos = ApiHookLogParams(
    "user32.dll", "GetCursorPos", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetWindowRect = ApiHookLogParams(
    "user32.dll", "GetWindowRect", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_ScreenToClient = ApiHookLogParams(
    "user32.dll", "ScreenToClient", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_ClientToScreen = ApiHookLogParams(
    "user32.dll", "ClientToScreen", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetForegroundWindow = ApiHookLogParams(
    "user32.dll", "GetForegroundWindow", group_name="win_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 窗口 - gui32.dll


hook_CreateCompatibleDC = ApiHookLogParams(
    "gdi32.dll", "CreateCompatibleDC", group_name="win_gdi32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_CreateCompatibleBitmap = ApiHookLogParams(
    "gdi32.dll", "CreateCompatibleBitmap", group_name="win_gdi32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_BitBlt = ApiHookLogParams(
    "gdi32.dll", "BitBlt", group_name="win_gdi32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 互斥体 - kernel32.dll


hook_ReleaseMutex = ApiHookLogParams(
    "kernel32.dll", "ReleaseMutex", group_name="mutex_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


hook_CreateMutexW = ApiHookCustom(
    "kernel32.dll", "CreateMutexW", handler_api_invoke=handler_CreateMutexW, group_name="mutex_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_OpenMutexW = ApiHookCustom(
    "kernel32.dll", "OpenMutexW", handler_api_invoke=handler_OpenMutexW, group_name="mutex_kernel32",
    weight=V_WEIGHT_MIDDLE
)


# ---------------------------------------------------------------------------
# 事件日志 - advapi32.dll


hook_OpenEventLogA = ApiHookLogParams(
    "advapi32.dll", "OpenEventLogA", group_name="evt_log_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "svr", V_PARAM_LOG_PASTR),
        ParamLogCtrl(8, "src", V_PARAM_LOG_PASTR)
    ],
    is_fragile=True
)

hook_OpenEventLogW = ApiHookLogParams(
    "advapi32.dll", "OpenEventLogW", group_name="evt_log_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "svr", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "src", V_PARAM_LOG_PUSTR)
    ],
    is_fragile=True
)

hook_ClearEventLogW = ApiHookLogParams(
    "advapi32.dll", "ClearEventLogW", group_name="evt_log_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "file", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)


# ---------------------------------------------------------------------------
# 权限 - advapi32.dll


hook_AdjustTokenPrivileges = ApiHookLogParams(
    "advapi32.dll", "AdjustTokenPrivileges", group_name="priv_advapi32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_LookupPrivilegeDisplayNameW = ApiHookLogParams(
    "advapi32.dll", "LookupPrivilegeDisplayNameW", group_name="priv_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "sys", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "name", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_LookupPrivilegeNameW = ApiHookLogParams(
    "advapi32.dll", "LookupPrivilegeNameW", group_name="priv_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "sys", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_LookupPrivilegeValueW = ApiHookLogParams(
    "advapi32.dll", "LookupPrivilegeValueW", group_name="priv_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "sys", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "name", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)


# ---------------------------------------------------------------------------
# 资源 - kernel32.dll


hook_FindResourceA = ApiHookCustom(
    "kernel32.dll", "FindResourceA", handler_api_invoke=handler_FindResourceA, group_name="res_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_FindResourceW = ApiHookCustom(
    "kernel32.dll", "FindResourceW", handler_api_invoke=handler_FindResourceW, group_name="res_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_FindResourceExA = ApiHookCustom(
    "kernel32.dll", "FindResourceExA", handler_api_invoke=handler_FindResourceExA, group_name="res_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_FindResourceExW = ApiHookCustom(
    "kernel32.dll", "FindResourceExW", handler_api_invoke=handler_FindResourceExW, group_name="res_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_LoadResource = ApiHookLogParams(
    "kernel32.dll", "LoadResource", group_name="res_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_LockResource = ApiHookLogParams(
    "kernel32.dll", "LockResource", group_name="res_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SizeofResource = ApiHookLogParams(
    "kernel32.dll", "SizeofResource", group_name="res_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_UpdateResourceW = ApiHookLogParams(
    "kernel32.dll", "UpdateResourceW", group_name="res_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(8, "res_type", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "res_name", V_PARAM_LOG_PUSTR)
    ],
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 管道 - kernel32.dll


hook_CreateNamedPipeW = ApiHookLogParams(
    "kernel32.dll", "CreateNamedPipeW", group_name="pipe_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "pipe", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_CreatePipe = ApiHookLogParams(
    "kernel32.dll", "CreatePipe", group_name="pipe_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_CallNamedPipeW = ApiHookLogParams(
    "kernel32.dll", "CallNamedPipeW", group_name="pipe_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "pipe", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_WaitNamedPipeW = ApiHookLogParams(
    "kernel32.dll", "WaitNamedPipeW", group_name="pipe_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "pipe", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_PeekNamedPipe = ApiHookLogParams(
    "kernel32.dll", "PeekNamedPipe", group_name="pipe_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_ConnectNamedPipe = ApiHookLogParams(
    "kernel32.dll", "ConnectNamedPipe", group_name="pipe_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_DisconnectNamedPipe = ApiHookLogParams(
    "kernel32.dll", "DisconnectNamedPipe", group_name="pipe_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 窗口钩子 - user32.dll


hook_SetWindowsHookA = ApiHookLogParams(
    "user32.dll", "SetWindowsHookA", group_name="hook_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "id", V_PARAM_LOG_INT),
        ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)
    ],
    is_fragile=True
)

hook_SetWindowsHookW = ApiHookLogParams(
    "user32.dll", "SetWindowsHookW", group_name="hook_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "id", V_PARAM_LOG_INT),
        ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)
    ],
    is_fragile=True
)

hook_SetWindowsHookExA = ApiHookLogParams(
    "user32.dll", "SetWindowsHookExA", group_name="hook_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "id", V_PARAM_LOG_INT),
        ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT),
        ParamLogCtrl(0x10, "tid", V_PARAM_LOG_INT)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_SetWindowsHookExW = ApiHookLogParams(
    "user32.dll", "SetWindowsHookExW", group_name="hook_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "id", V_PARAM_LOG_INT),
        ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT),
        ParamLogCtrl(0x10, "tid", V_PARAM_LOG_INT)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_CallNextHookEx = ApiHookLogParams(
    "user32.dll", "CallNextHookEx", group_name="hook_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "code", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_UnhookWindowsHook = ApiHookLogParams(
    "user32.dll", "UnhookWindowsHook", group_name="hook_user32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "code", V_PARAM_LOG_INT)],
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 环境 - kernel32.dll


hook_GetEnvironmentStringsA = ApiHookLogParams(
    "kernel32.dll", "GetEnvironmentStringsA", group_name="env_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetEnvironmentStringsW = ApiHookLogParams(
    "kernel32.dll", "GetEnvironmentStringsW", group_name="env_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetEnvironmentVariableA = ApiHookLogParams(
    "kernel32.dll", "GetEnvironmentVariableA", group_name="env_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "name", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_GetEnvironmentVariableW = ApiHookLogParams(
    "kernel32.dll", "GetEnvironmentVariableW", group_name="env_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_SetEnvironmentVariableA = ApiHookLogParams(
    "kernel32.dll", "SetEnvironmentVariableA", group_name="env_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(8, "value", V_PARAM_LOG_PASTR)
    ],
    is_fragile=True
)

hook_SetEnvironmentVariableW = ApiHookLogParams(
    "kernel32.dll", "SetEnvironmentVariableW", group_name="env_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "value", V_PARAM_LOG_PUSTR)
    ],
    is_fragile=True
)

hook_ExpandEnvironmentStringsA = ApiHookCustom(
    "kernel32.dll", "ExpandEnvironmentStringsA", handler_api_invoke=handler_ExpandEnvironmentStringsA, group_name="env_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_ExpandEnvironmentStringsW = ApiHookCustom(
    "kernel32.dll", "ExpandEnvironmentStringsW", handler_api_invoke=handler_ExpandEnvironmentStringsW, group_name="env_kernel32",
    weight=V_WEIGHT_MIDDLE
)


# ---------------------------------------------------------------------------
# 配置文件 - kernel32.dll


hook_GetPrivateProfileStringA = ApiHookCustom(
    "kernel32.dll", "GetPrivateProfileStringA", handler_api_invoke=handler_GetPrivateProfileStringA, group_name="profile_kernel32",
    cstk_filter_depth=3, weight=V_WEIGHT_MIDDLE
)

hook_GetPrivateProfileStringW = ApiHookCustom(
    "kernel32.dll", "GetPrivateProfileStringW", handler_api_invoke=handler_GetPrivateProfileStringW, group_name="profile_kernel32",
    cstk_filter_depth=3, weight=V_WEIGHT_MIDDLE
)

hook_GetPrivateProfileSectionA = ApiHookLogParams(
    "kernel32.dll", "GetPrivateProfileSectionA", group_name="profile_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "app_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x10, "file", V_PARAM_LOG_PASTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_GetPrivateProfileSectionW = ApiHookLogParams(
    "kernel32.dll", "GetPrivateProfileSectionW", group_name="profile_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "app_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "file", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_WritePrivateProfileSectionA = ApiHookLogParams(
    "kernel32.dll", "WritePrivateProfileSectionA", group_name="profile_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "app_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(8, "value", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "file", V_PARAM_LOG_PASTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_WritePrivateProfileSectionW = ApiHookLogParams(
    "kernel32.dll", "WritePrivateProfileSectionW", group_name="profile_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "app_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "value", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_WritePrivateProfileStringA = ApiHookLogParams(
    "kernel32.dll", "WritePrivateProfileStringA", group_name="profile_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "app_name", V_PARAM_LOG_PASTR),
        ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0xC, "value", V_PARAM_LOG_PASTR),
        ParamLogCtrl(0x10, "file", V_PARAM_LOG_PASTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)

hook_WritePrivateProfileStringW = ApiHookLogParams(
    "kernel32.dll", "WritePrivateProfileStringW", group_name="profile_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "app_name", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0xC, "value", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "file", V_PARAM_LOG_PUSTR)
    ],
    cstk_filter_depth=2, is_fragile=True
)


# ---------------------------------------------------------------------------
# 事件 - kernel32.dll


hook_OpenEventW = ApiHookLogParams(
    "kernel32.dll", "OpenEventW", group_name="evt_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(0xC, "evt", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_SetEvent = ApiHookLogParams(
    "kernel32.dll", "SetEvent", group_name="evt_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_ResetEvent = ApiHookLogParams(
    "kernel32.dll", "ResetEvent", group_name="evt_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_PulseEvent = ApiHookLogParams(
    "kernel32.dll", "PulseEvent", group_name="evt_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 计时器 - user32.dll


hook_SetTimer = ApiHookCustom(
    "user32.dll", "SetTimer", handler_api_invoke=handler_SetTimer, group_name="timer_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_SetSystemTimer = ApiHookLogParams(
    "user32.dll", "SetSystemTimer", group_name="timer_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_KillTimer = ApiHookCustom(
    "user32.dll", "KillTimer", handler_api_invoke=handler_KillTimer, group_name="timer_user32",
    weight=V_WEIGHT_MIDDLE
)

hook_KillSystemTimer = ApiHookLogParams(
    "user32.dll", "KillSystemTimer", group_name="timer_user32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 原子变量 - kernel32.dll


hook_InitAtomTable = ApiHookLogParams(
    "kernel32.dll", "InitAtomTable", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "size", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_AddAtomA = ApiHookLogParams(
    "kernel32.dll", "AddAtomA", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_AddAtomW = ApiHookLogParams(
    "kernel32.dll", "AddAtomW", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_DeleteAtom = ApiHookLogParams(
    "kernel32.dll", "DeleteAtom", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    is_fragile=True
)

hook_FindAtomA = ApiHookLogParams(
    "kernel32.dll", "FindAtomA", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_FindAtomW = ApiHookLogParams(
    "kernel32.dll", "FindAtomW", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_GetAtomNameA = ApiHookLogParams(
    "kernel32.dll", "GetAtomNameA", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetAtomNameW = ApiHookLogParams(
    "kernel32.dll", "GetAtomNameW", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GlobalAddAtomA = ApiHookLogParams(
    "kernel32.dll", "GlobalAddAtomA", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_GlobalAddAtomW = ApiHookLogParams(
    "kernel32.dll", "GlobalAddAtomW", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_GlobalDeleteAtom = ApiHookLogParams(
    "kernel32.dll", "GlobalDeleteAtom", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GlobalFindAtomA = ApiHookLogParams(
    "kernel32.dll", "GlobalFindAtomA", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)],
    is_fragile=True
)

hook_GlobalFindAtomW = ApiHookLogParams(
    "kernel32.dll", "GlobalFindAtomW", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_GlobalGetAtomNameA = ApiHookLogParams(
    "kernel32.dll", "GlobalGetAtomNameA", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GlobalGetAtomNameW = ApiHookLogParams(
    "kernel32.dll", "GlobalGetAtomNameW", group_name="atom_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# COM - ole32.dll


hook_CoInitializeEx = ApiHookLogParams(
    "ole32.dll", "CoInitializeEx", group_name="com_ole32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_CoCreateInstanceEx = ApiHookLogParams(
    "ole32.dll", "CoCreateInstanceEx", group_name="com_ole32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_CoUninitialize = ApiHookLogParams(
    "ole32.dll", "CoUninitialize", group_name="com_ole32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 内存 - kernel32.dll/ntdll.dll


hook_VirtualAllocEx = ApiHookCustom(
    "kernel32.dll", "VirtualAllocEx", handler_api_invoke=handler_VirtualAllocEx, group_name="mm_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_VirtualProtectEx = ApiHookCustom(
    "kernel32.dll", "VirtualProtectEx", handler_api_invoke=handler_VirtualProtectEx, group_name="mm_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_RtlReAllocateHeap = ApiHookLogParams(
    "kernel32.dll", "RtlReAllocateHeap", group_name="mm_ntdll", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(0x10, "size", V_PARAM_LOG_INT)],
    is_fragile=True
)


# ---------------------------------------------------------------------------
# .NET - mscoree.dll


hook_CLRCreateInstance = ApiHookLogParams(
    "mscoree.dll", "CLRCreateInstance", group_name="dotnet_mscoree", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)],
    is_fragile=True
)

hook_CorBindToRuntimeEx = ApiHookLogParams(
    "mscoree.dll", "CorBindToRuntimeEx", group_name="dotnet_mscoree", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "version", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "flavor", V_PARAM_LOG_PUSTR)
    ],
    is_fragile=True
)

hook_CorExitProcess = ApiHookLogParams(
    "mscoree.dll", "CorExitProcess", group_name="dotnet_mscoree", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# dbghelp - dbghelp.dll


hook_MiniDumpWriteDump = ApiHookCustom(
    "dbghelp.dll", "MiniDumpWriteDump", handler_api_invoke=handler_MiniDumpWriteDump, group_name="dbghelp_dbghelp",
    weight=V_WEIGHT_MIDDLE
)

hook_StackWalk64 = ApiHookLogParams(
    "dbghelp.dll", "StackWalk64", group_name="dbghelp_dbghelp", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SymFunctionTableAccess64 = ApiHookLogParams(
    "dbghelp.dll", "SymFunctionTableAccess64", group_name="dbghelp_dbghelp", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SymGetModuleBase64 = ApiHookLogParams(
    "dbghelp.dll", "SymGetModuleBase64", group_name="dbghelp_dbghelp", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

# ---------------------------------------------------------------------------
# 其他 - kernel32.dll


hook_SleepEx = ApiHookCustom(
    "kernel32.dll", "SleepEx", handler_api_invoke=handler_SleepEx, group_name="misc_kernel32",
    weight=V_WEIGHT_CRITICAL, cstk_filter_depth=2
)

hook_TerminateProcess = ApiHookCustom(
    "kernel32.dll", "TerminateProcess", handler_api_invoke=handler_TerminateProcess, group_name="misc_kernel32",
    weight=V_WEIGHT_CRITICAL
)

hook_ExitProcess = ApiHookCustom(
    "kernel32.dll", "ExitProcess", handler_api_invoke=handler_ExitProcess, group_name="misc_kernel32",
    weight=V_WEIGHT_CRITICAL
)

hook_GetProcAddress = ApiHookCustom(
    "kernel32.dll", "GetProcAddress", handler_api_invoke=handler_GetProcAddress, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_LoadLibraryExW = ApiHookLogParams(
    "kernel32.dll", "LoadLibraryExW", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=3, is_fragile=True
)

hook_IsDebuggerPresent = ApiHookLogParams(
    "kernel32.dll", "IsDebuggerPresent", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SetErrorMode = ApiHookCustom(
    "kernel32.dll", "SetErrorMode", handler_api_invoke=handler_SetErrorMode, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_SetUnhandledExceptionFilter = ApiHookLogParams(
    "kernel32.dll", "SetUnhandledExceptionFilter", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "cbk", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_GetComputerNameW = ApiHookCustom(
    "kernel32.dll", "GetComputerNameW", handler_api_invoke=handler_GetComputerNameW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_GetComputerNameExW = ApiHookCustom(
    "kernel32.dll", "GetComputerNameExW", handler_api_invoke=handler_GetComputerNameExW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_SetComputerNameW = ApiHookLogParams(
    "kernel32.dll", "SetComputerNameW", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_SetComputerNameExW = ApiHookLogParams(
    "kernel32.dll", "SetComputerNameExW", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(8, "name", V_PARAM_LOG_PUSTR)],
    cstk_filter_depth=2, is_fragile=True
)

hook_GetCurrentDirectoryA = ApiHookCustom(
    "kernel32.dll", "GetCurrentDirectoryA", handler_api_invoke=handler_GetCurrentDirectoryA, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_GetCurrentDirectoryW = ApiHookCustom(
    "kernel32.dll", "GetCurrentDirectoryW", handler_api_invoke=handler_GetCurrentDirectoryW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_GetModuleFileNameW = ApiHookCustom(
    "kernel32.dll", "GetModuleFileNameW", handler_api_invoke=handler_GetModuleFileNameW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_GetVersion = ApiHookCustom(
    "kernel32.dll", "GetVersion", handler_api_invoke=handler_GetVersion, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_GetVersionExW = ApiHookCustom(
    "kernel32.dll", "GetVersionExW", handler_api_invoke=handler_GetVersionExW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_GetCommandLineA = ApiHookCustom(
    "kernel32.dll", "GetCommandLineA", handler_api_invoke=handler_GetCommandLineA, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_GetCommandLineW = ApiHookCustom(
    "kernel32.dll", "GetCommandLineW", handler_api_invoke=handler_GetCommandLineW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_GetStartupInfoA = ApiHookLogParams(
    "kernel32.dll", "GetStartupInfoA", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetStartupInfoW = ApiHookLogParams(
    "kernel32.dll", "GetStartupInfoW", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_OutputDebugStringA = ApiHookLogParams(
    "kernel32.dll", "OutputDebugStringA", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)],
    is_fragile=True, cstk_filter_depth=2, max_invoke_cnt_runtime=100
)

hook_GetTickCount = ApiHookCustom(
    "kernel32.dll", "GetTickCount", handler_api_invoke=handler_GetTickCount, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, max_invoke_cnt_runtime=50
)

hook_GetSystemTime = ApiHookCustom(
    "kernel32.dll", "GetSystemTime", handler_api_invoke=handler_GetSystemTime, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_QueueUserAPC = ApiHookLogParams(
    "kernel32.dll", "QueueUserAPC", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "cbk", V_PARAM_LOG_INT)],
    is_fragile=True
)

hook_CreateMailslotW = ApiHookLogParams(
    "kernel32.dll", "CreateMailslotW", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)],
    is_fragile=True, cstk_filter_depth=2
)

hook_SetSystemPowerState = ApiHookLogParams(
    "kernel32.dll", "SetSystemPowerState", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "is_suspend", V_PARAM_LOG_INT),
        ParamLogCtrl(8, "is_force", V_PARAM_LOG_INT)
    ],
    is_fragile=True
)

hook_SetSystemTime = ApiHookLogParams(
    "kernel32.dll", "SetSystemTime", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    is_fragile=True
)

hook_SetSystemTimeAdjustment = ApiHookLogParams(
    "kernel32.dll", "SetSystemTimeAdjustment", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[],
    is_fragile=True
)

hook_GetModuleHandleW = ApiHookCustom(
    "kernel32.dll", "GetModuleHandleW", handler_api_invoke=handler_GetModuleHandleW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_GetModuleHandleExW = ApiHookCustom(
    "kernel32.dll", "GetModuleHandleExW", handler_api_invoke=handler_GetModuleHandleExW, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_DisableThreadLibraryCalls = ApiHookLogParams(
    "kernel32.dll", "DisableThreadLibraryCalls", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_FileTimeToSystemTime = ApiHookLogParams(
    "kernel32.dll", "FileTimeToSystemTime", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SystemTimeToFileTime = ApiHookLogParams(
    "kernel32.dll", "SystemTimeToFileTime", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_SetProcessDEPPolicy = ApiHookLogParams(
    "kernel32.dll", "SetProcessDEPPolicy", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_CreateIoCompletionPort = ApiHookLogParams(
    "kernel32.dll", "CreateIoCompletionPort", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_BindIoCompletionCallback = ApiHookLogParams(
    "kernel32.dll", "BindIoCompletionCallback", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_PostQueuedCompletionStatus = ApiHookLogParams(
    "kernel32.dll", "PostQueuedCompletionStatus", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetQueuedCompletionStatus = ApiHookLogParams(
    "kernel32.dll", "GetQueuedCompletionStatus", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_IsProcessorFeaturePresent = ApiHookCustom(
    "kernel32.dll", "IsProcessorFeaturePresent", handler_api_invoke=handler_IsProcessorFeaturePresent, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE
)

hook_CreateHardLinkW = ApiHookLogParams(
    "kernel32.dll", "CreateHardLinkW", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(4, "file_new", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(8, "old_file", V_PARAM_LOG_PUSTR)
    ],
    is_fragile=True, cstk_filter_depth=2
)

hook_GetLogicalProcessorInformation = ApiHookLogParams(
    "kernel32.dll", "GetLogicalProcessorInformation", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_GetNativeSystemInfo = ApiHookLogParams(
    "kernel32.dll", "GetNativeSystemInfo", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_WaitForSingleObjectEx = ApiHookCustom(
    "kernel32.dll", "WaitForSingleObjectEx", handler_api_invoke=handler_WaitForSingleObjectEx, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_WaitForMultipleObjectsEx = ApiHookCustom(
    "kernel32.dll", "WaitForMultipleObjectsEx", handler_api_invoke=handler_WaitForMultipleObjectsEx, group_name="misc_kernel32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_CreateEventW = ApiHookLogParams(
    "kernel32.dll", "CreateEventW", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(0x10, "evt", V_PARAM_LOG_PUSTR)],
    is_fragile=True, cstk_filter_depth=2
)

hook_RaiseException = ApiHookLogParams(
    "kernel32.dll", "RaiseException", group_name="misc_kernel32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 其他 - mpr.dll


hook_WNetUseConnectionW = ApiHookLogParams(
    "mpr.dll", "WNetUseConnectionW", group_name="misc_mpr", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[
        ParamLogCtrl(0xC, "pwd", V_PARAM_LOG_PUSTR),
        ParamLogCtrl(0x10, "userid", V_PARAM_LOG_PUSTR)
    ],
    is_fragile=True, cstk_filter_depth=3
)


# ---------------------------------------------------------------------------
# 其他 - psapi.dll


hook_GetModuleFileNameExW = ApiHookCustom(
    "psapi.dll", "GetModuleFileNameExW", handler_api_invoke=handler_GetModuleFileNameExW, group_name="misc_psapi",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=2
)

hook_GetProcessImageFileNameA = ApiHookCustom(
    "psapi.dll", "GetProcessImageFileNameA", handler_api_invoke=handler_GetProcessImageFileNameA, group_name="misc_psapi",
    weight=V_WEIGHT_MIDDLE
)

hook_GetProcessImageFileNameW = ApiHookCustom(
    "psapi.dll", "GetProcessImageFileNameW", handler_api_invoke=handler_GetProcessImageFileNameW, group_name="misc_psapi",
    weight=V_WEIGHT_MIDDLE
)


# ---------------------------------------------------------------------------
# 其他 - msvcrt.dll


hook__access = ApiHookCustom(
    "msvcrt.dll", "_access", handler_api_invoke=handler_access, group_name="misc_msvcrt",
    weight=V_WEIGHT_MIDDLE
)


# ---------------------------------------------------------------------------
# 其他 - msi.dll


hook_MsiViewFetch = ApiHookLogParams(
    "msi.dll", "MsiViewFetch", group_name="misc_msi", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)


# ---------------------------------------------------------------------------
# 其他 - shell32.dll


hook_ShellExecuteExW = ApiHookCustom(
    "shell32.dll", "ShellExecuteExW", handler_api_invoke=handler_ShellExecuteExW, group_name="misc_shell32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=3
)

hook_SHGetFolderPathW = ApiHookCustom(
    "shell32.dll", "SHGetFolderPathW", handler_api_invoke=handler_SHGetFolderPathW, group_name="misc_shell32",
    weight=V_WEIGHT_MIDDLE, cstk_filter_depth=3
)


# ---------------------------------------------------------------------------
# 其他 - advapi32.dll


hook_OpenProcessToken = ApiHookLogParams(
    "advapi32.dll", "OpenProcessToken", group_name="misc_advapi32", weight=V_WEIGHT_MIDDLE,
    is_fragile=True
)

hook_EncryptFileW = ApiHookLogParams(
    "advapi32.dll", "EncryptFileW", group_name="misc_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)],
    is_fragile=True, cstk_filter_depth=2
)

hook_DecryptFileW = ApiHookLogParams(
    "advapi32.dll", "DecryptFileW", group_name="misc_advapi32", weight=V_WEIGHT_MIDDLE,
    param_log_ctrl_list=[ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)],
    is_fragile=True, cstk_filter_depth=2
)


# ---------------------------------------------------------------------------
# 其他 - ntdll.dll


hook_ZwDelayExecution = ApiHookCustom(
    "ntdll.dll", "ZwDelayExecution", handler_api_invoke=handler_ZwDelayExecution, group_name="misc_ntdll",
    weight=V_WEIGHT_MIDDLE
)

hook_NtQueryInformationProcess = ApiHookCustom(
    "ntdll.dll", "NtQueryInformationProcess", handler_api_invoke=handler_NtQueryInformationProcess, group_name="misc_ntdll",
    weight=V_WEIGHT_MIDDLE
)

hook_NtQueryInformationThread = ApiHookCustom(
    "ntdll.dll", "NtQueryInformationThread", handler_api_invoke=handler_NtQueryInformationThread, group_name="misc_ntdll",
    weight=V_WEIGHT_MIDDLE
)

hook_NtSetInformationProcess = ApiHookCustom(
    "ntdll.dll", "NtSetInformationProcess", handler_api_invoke=handler_NtSetInformationProcess, group_name="misc_ntdll",
    weight=V_WEIGHT_MIDDLE
)


# ---------------------------------------------------------------------------
#

if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
