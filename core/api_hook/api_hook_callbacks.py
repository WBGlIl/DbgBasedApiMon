# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# # from __future__ import unicode_literals

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))                   # core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))  # repo-pydbg

from _util.util import *
from _util.msdn import msdn
# from _util.sym import sym
from util_dbg import *
from api_hook_config import api_global_config  # api_config,


# ---------------------------------------------------------------------------
# 变量


# 运行时回调中用到的某些临时变量放到这里
callback_runtime = {}


# ---------------------------------------------------------------------------
# util -


def retn_True(params=None, meta_list=None):
    return (params, meta_list, True)


def retn_False(params=None, meta_list=None):
    return (params, meta_list, False)


# ---------------------------------------------------------------------------
# 回调函数


def handler_RegSetValueExA(self, dbg):
    """
        parse params

        advapi32.RegSetValueExA

        RegSetValueA-->RegSetValueExA-->BaseRegSetValue/LocalBaseRegSetValue
          _In_             HKEY    hKey,
          _In_opt_         LPCTSTR lpValueName,
          _Reserved_       DWORD   Reserved,
          _In_             DWORD   dwType,
          _In_       const BYTE    *lpData,
          _In_             DWORD   cbData
    """
    reg_value = read_stack_p_ascii_string(dbg, 8)
    type_ = read_stack_int32(dbg, 0x10)
    pdata = read_stack_int32(dbg, 0x14)
    data_size = read_stack_int32(dbg, 0x18)
    type_str, reg_data = get_reg_data(dbg, type_, pdata, data_size)

    params = {"reg_value": reg_value, "type": type_str, "data": reg_data}
    return retn_True(params=params)


def handler_RegSetValueExW(dbg):
    """
        parse params

        advapi32.RegSetValueExW

        RegSetValueW-->RegSetValueExW-->BaseRegSetValue/LocalBaseRegSetValue

          _In_             HKEY    hKey,
          _In_opt_         LPCTSTR lpValueName,
          _Reserved_       DWORD   Reserved,
          _In_             DWORD   dwType,
          _In_       const BYTE    *lpData,
          _In_             DWORD   cbData
    """
    reg_value = read_stack_p_unicode_string(dbg, 8)
    type_ = read_stack_int32(dbg, 0x10)
    pdata = read_stack_int32(dbg, 0x14)
    data_size = read_stack_int32(dbg, 0x18)
    type_str, reg_data = get_reg_data(dbg, type_, pdata, data_size)

    params = {"reg_value": reg_value, "type": type_str, "data": reg_data}
    return retn_True(params)


v_dict_sock_af = {0: "AF_UNSPEC", 2: "AF_INET", 6: "AF_IPX", 16: "AF_APPLETALK", 17: "AF_NETBIOS", 23: "AF_INET6", 26: "AF_IRDA", 32: "AF_BTH"}
v_dict_sock_type = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 4: "SOCK_RDM", 5: "SOCK_SEQPACKET"}
v_dict_sock_protocol = {0: "IPPROTO_RAW", 1: "IPPROTO_ICMP", 2: "IPPROTO_IGMP", 3: "BTHPROTO_RFCOMM", 6: "IPPROTO_TCP", 17: "IPPROTO_UDP", 58: "IPPROTO_ICMPV6", 113: "IPPROTO_RM"}


def handler_ret_WSASocketW(dbg):
    """
        modify result
    """
    assert api_global_config["is_all_socket_success"]

    if dbg.context.Eax == 0xFFFFFFFF:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "WSASocketW", extrainfo="force ret from 0xFFFFFFFF to 0")
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "WSASocketW", extrainfo="intrude debugee not allowed, so we cancel it")


def handler_WSASocketW(dbg):
    """
        parse param, and modify ret

        ws2_32.WSASocketW

        socket-->WSASocketW
        WSASocketA-->WSASocketW

          _In_ int                af,
          _In_ int                type,
          _In_ int                protocol,
          _In_ LPWSAPROTOCOL_INFO lpProtocolInfo,
          _In_ GROUP              g,
          _In_ DWORD              dwFlags
    """
    if api_global_config["is_all_socket_success"]:
        # 00004114 - 0000404E = 0xC6
        dbg.install_hook_by_tid(dbg.cur_eip() + 0xC6, callback=handler_ret_WSASocketW)

    af = read_stack_int32(dbg, 4)
    type_ = read_stack_int32(dbg, 8)
    protocol = read_stack_int32(dbg, 0xC)

    af_str = af not in v_dict_sock_af and ("%X" % af) or v_dict_sock_af[af]
    type_str = type_ not in v_dict_sock_type and ("%X" % type_) or v_dict_sock_type[type_]
    protocol_str = protocol not in v_dict_sock_protocol and ("%X" % protocol) or v_dict_sock_protocol[protocol]

    params = {"af": af_str, "type": type_str, "protocol": protocol_str}
    return retn_True(params)


def handler_getsockname(dbg):
    """
        parse param

        ws2_32.getsockname

          SOCKET s,
          struct sockaddr FAR* name,
          int FAR* namelen
    """
    p_addr = read_stack_int32(dbg, 8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    params = {"addr": "%s:%d" % (ip_str, port)}
    return retn_True(params)


def handler_ret_gethostname(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_gethostname" in callback_runtime

    result_str = read_ascii_string(dbg, callback_runtime["addr_result_gethostname"])
    _xrk_api_invoke_retn_detail(dbg, "gethostname", ret_dict={"host_name": result_str})

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    del callback_runtime["addr_result_gethostname"]

    return defines.DBG_CONTINUE


def handler_gethostname(dbg):
    """
        record result

        ws2_32.gethostname

          _Out_ char *name,
          _In_  int  namelen
    """
    global callback_runtime
    assert "addr_result_gethostname" not in callback_runtime

    callback_runtime["addr_result_gethostname"] = read_stack_int32(dbg, 4)
    # 00005557 - 00005449 = 0x10E
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x10E, callback=handler_ret_gethostname)

    return retn_True()


def handler_ret_gethostbyname(dbg):
    """
        record results
    """
    p_hostent = dbg.context.Eax
    desc_str = parse_hostent(dbg, p_hostent)

    _xrk_api_invoke_retn_detail(dbg, "gethostbyname", ret_dict={"host": desc_str})

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_gethostbyname(dbg):
    """
        record results

        ws2_32.gethostbyname

          _In_ const char *name
    """
    name = read_stack_p_ascii_string(dbg, 4)

    # 00005441 - 00005355 = 0xEC
    dbg.install_hook_by_tid(dbg.cur_eip() + 0xEC, callback=handler_ret_gethostbyname)

    params = {"name": name}
    return retn_True(params)


def handler_ret_bind(dbg):
    """
        modify ret
    """
    assert api_global_config["is_all_socket_success"] is True

    if dbg.context.Eax != 0:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "bind", extrainfo="force ret from %d to 0" % dbg.context.Eax)
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "bind", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_bind(dbg):
    """
        parse param, and modify ret

        ws2_32.bind

          _In_ SOCKET                s,
          _In_ const struct sockaddr *name,
          _In_ int                   namelen
    """
    if api_global_config["is_all_socket_success"]:
        # 000044E3 - 00004480 = 0x63
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x63, callback=handler_ret_bind)

    p_addr = read_stack_int32(dbg, 8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    params = {"addr": "%s:%d" % (ip_str, port)}
    return retn_True(params)


def handler_ret_connect(dbg):
    """
        modify ret
    """
    assert api_global_config["is_all_socket_success"] is True

    if dbg.context.Eax != 0:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "connect", extrainfo="force ret from %d to 0" % dbg.context.Eax)
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "connect", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_connect(dbg):
    """
        param param, and modify ret

        ws2_32.connect

          SOCKET s,
          const struct sockaddr FAR* name,
          int namelen
    """
    if api_global_config["is_all_socket_success"]:
        # 00004A7B - 00004A07 = 0x74
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x74, callback=handler_ret_connect)

    p_addr = read_stack_int32(dbg, 8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    params = {"addr": "%s:%d" % (ip_str, port)}
    extrainfo = None

    if len(api_global_config["connect_redirect_ip"]) != 0:

        new_sock_connect_ip = ipstr_to_value(api_global_config["connect_redirect_ip"])
        assert len(new_sock_connect_ip) == 4
        dbg.write(p_addr + 4, new_sock_connect_ip, 4)
        extrainfo = ">>> modified to some new address <<<"

    if api_global_config["connect_redirect_port"] != 0 and port != api_global_config["connect_redirect_port"]:

        assert api_global_config["connect_redirect_port"] > 0 and api_global_config["connect_redirect_port"] < 65535
        write_int16(dbg, p_addr + 2, api_global_config["connect_redirect_port"])
        extrainfo_x = ">>> modified to some new port <<<"
        extrainfo = extrainfo is None and extrainfo_x or extrainfo + extrainfo_x

    return retn_True(params, extrainfo)


def handler_send(dbg):
    """
        save send data

        ws2_32.send

          _In_       SOCKET s,
          _In_ const char   *buf,
          _In_       int    len,
          _In_       int    flags
    """
    addr = read_stack_int32(dbg, 8)
    len_ = read_stack_int32(dbg, 0xC)

    if api_global_config["is_save_send_data_to_file"]:
        data = dbg.read(addr, len_)
        util.save_buf_to_file("send", data)

    params = {"addr": "%.8X" % addr, "len": "%.8X" % len_}
    return retn_True(params)


def handler_sendto(dbg):
    """
        save send data

        ws2_32.sendto

          _In_       SOCKET                s,
          _In_ const char                  *buf,
          _In_       int                   len,
          _In_       int                   flags,
          _In_       const struct sockaddr *to,
          _In_       int                   tolen
    """
    addr = read_stack_int32(dbg, 8)
    len_ = read_stack_int32(dbg, 0xC)

    if api_global_config["is_save_send_data_to_file"]:
        data = dbg.read(addr, len_)
        util.save_buf_to_file("sendto", data)

    params = {"addr": "%.8X" % addr, "len": "%.8X" % len_}
    return retn_True(params)


def handler_ret_recv(dbg):
    """
        save result
    """
    global callback_runtime
    assert "addr_result_recv" in callback_runtime

    len_ = dbg.context.Eax
    _xrk_api_invoke_retn_detail(dbg, "recv", ret_dict={"size_recved": "%d" % len_})

    if api_global_config["is_save_recv_data_to_file"]:
        data = dbg.read(callback_runtime["addr_result_recv"], len_)
        util.save_buf_to_file("recv", data)

    del callback_runtime["addr_result_recv"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_recv(dbg):
    """
        record recv result

        ws2_32.recv

          _In_   SOCKET s,
          _Out_  char *buf,
          _In_   int len,
          _In_   int flags
    """
    result_addr = read_stack_int32(dbg, 8)

    global callback_runtime
    assert "addr_result_recv" not in callback_runtime

    callback_runtime["addr_result_recv"] = result_addr

    # 00006800 - 0000676F = 0x91
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x91, callback=handler_ret_recv)

    return retn_True()


def handler_ret_recvfrom(dbg):
    """
        save result
    """
    global callback_runtime
    assert "addr_result_recvfrom" in callback_runtime

    len_ = dbg.context.Eax
    _xrk_api_invoke_retn_detail(dbg, "recvfrom", ret_dict={"recved_len": "%d" % len_})

    if api_global_config["is_save_recv_data_to_file"]:
        data = dbg.read(callback_runtime["addr_result_recvfrom"], len_)
        util.save_buf_to_file("recvfrom", data)

    del callback_runtime["addr_result_recvfrom"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_recvfrom(dbg):
    """
        record recv result

        ws2_32.recvfrom

          _In_        SOCKET          s,
          _Out_       char            *buf,
          _In_        int             len,
          _In_        int             flags,
          _Out_       struct sockaddr *from,
          _Inout_opt_ int             *fromlen
    """
    result_addr = read_stack_int32(dbg, 8)

    global callback_runtime
    assert "addr_result_recvfrom" not in callback_runtime

    callback_runtime["addr_result_recvfrom"] = result_addr

    # 000030A0 - 00002FF7 = 0xA9
    dbg.install_hook_by_tid(dbg.cur_eip() + 0xA9, callback=handler_ret_recvfrom)

    return retn_True()


def handler_ret_select(dbg):
    """
        modify ret
    """
    assert api_global_config["is_all_socket_success"] is True

    if dbg.context.Eax == 0xFFFFFFFF or dbg.context.Eax == 0:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "select", extrainfo="force ret from %d to 1" % dbg.context.Eax)
            dbg.set_register("EAX", 1)

        else:
            _xrk_api_invoke_retn_detail(dbg, "select", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_select(dbg):
    """
        modify ret

        ws2_32.select

        select-->DSOCKET::GetCountedDSocketFromSocket/...

          _In_    int                  nfds,
          _Inout_ fd_set               *readfds,
          _Inout_ fd_set               *writefds,
          _Inout_ fd_set               *exceptfds,
          _In_    const struct timeval *timeout
    """
    if api_global_config["is_all_socket_success"]:
        # 00003168 - 000030A8 = 0xC0
        dbg.install_hook_by_tid(dbg.cur_eip() + 0xC0, callback=handler_ret_select)

    return retn_True()


def handler_ret_setsockopt(dbg):
    """
        modify ret
    """
    assert api_global_config["is_all_socket_success"] is True

    if dbg.context.Eax != 0:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "setsockopt", extrainfo="force ret from %d to 0" % dbg.context.Eax)
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "setsockopt", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_setsockopt(dbg):
    """
        modify ret

        ws2_32.setsockopt

        setsockopt-->DSOCKET::GetCountedDSocketFromSocket/...

          _In_       SOCKET s,
          _In_       int    level,
          _In_       int    optname,
          _In_ const char   *optval,
          _In_       int    optlen
    """
    if api_global_config["is_all_socket_success"]:
        # 000045AD - 00004521 = 0x8C
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x8C, callback=handler_ret_setsockopt)

    return retn_True()


def handler_WSAConnect(dbg):
    """
        parse param and modify ret

        ws2_32.WSAConnect

          _In_  SOCKET                s,
          _In_  const struct sockaddr *name,
          _In_  int                   namelen,
          _In_  LPWSABUF              lpCallerData,
          _Out_ LPWSABUF              lpCalleeData,
          _In_  LPQOS                 lpSQOS,
          _In_  LPQOS                 lpGQOS
    """
    if api_global_config["is_all_socket_success"]:
        # 00010D13 - 00010C81 = 0x92
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x92, callback=handler_ret_WSAConnect)

    p_addr = read_stack_int32(dbg, 8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    params = {"addr": "%s:%d" % (ip_str, port)}
    extrainfo = None

    if len(api_global_config["connect_redirect_ip"]) != 0:

        new_sock_connect_ip = ipstr_to_value(api_global_config["connect_redirect_ip"])
        assert len(new_sock_connect_ip) == 4
        dbg.write(p_addr + 4, new_sock_connect_ip, 4)
        extrainfo = ">>> modified to some new address <<<"

    if api_global_config["connect_redirect_port"] != 0 and port != api_global_config["connect_redirect_port"]:

        assert api_global_config["connect_redirect_port"] > 0 and api_global_config["connect_redirect_port"] < 65535
        write_int16(dbg, p_addr + 2, api_global_config["connect_redirect_port"])
        extrainfo_x = ">>> modified to some new port <<<"
        extrainfo = extrainfo is None and extrainfo_x or extrainfo + extrainfo_x

    return retn_True(params, extrainfo)


def handler_WSASend(dbg):
    """
        parse param, and save send data

        ws2_32.WSASend

          _In_  SOCKET                             s,
          _In_  LPWSABUF                           lpBuffers,
          _In_  DWORD                              dwBufferCount,
          _Out_ LPDWORD                            lpNumberOfBytesSent,
          _In_  DWORD                              dwFlags,
          _In_  LPWSAOVERLAPPED                    lpOverlapped,
          _In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    buf_array = read_stack_int32(dbg, 8)
    buf_cnt = read_stack_int32(dbg, 0xC)

    size = 0
    for i in range(buf_cnt):

        len_i = read_int32(dbg, buf_array + i * 8)  # 8 is size of WSABUF structure
        buf_i = read_int32(dbg, buf_array + i * 8 + 4)

        size = size + len_i

        if api_global_config["is_save_send_data_to_file"]:
            data_i = dbg.read(buf_i, len_i)
            util.save_buf_to_file("WASSend_%d" % i, data_i)

    params = {"buf_cnt": "%d" % buf_cnt, "size_send": "%.8X" % size}
    return retn_True(params)


def handler_WSASendTo(dbg):
    """
        parse param and save send data

        ws2_32.WSASendTo

          _In_  SOCKET                             s,
          _In_  LPWSABUF                           lpBuffers,
          _In_  DWORD                              dwBufferCount,
          _Out_ LPDWORD                            lpNumberOfBytesSent,
          _In_  DWORD                              dwFlags,
          _In_  const struct sockaddr              *lpTo,
          _In_  int                                iToLen,
          _In_  LPWSAOVERLAPPED                    lpOverlapped,
          _In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    buf_array = read_stack_int32(dbg, 8)
    buf_cnt = read_stack_int32(dbg, 0xC)

    size = 0
    for i in range(buf_cnt):

        len_i = read_int32(dbg, buf_array + i * 8)  # 8 is size of WSABUF structure
        buf_i = read_int32(dbg, buf_array + i * 8 + 4)

        size = size + len_i

        if api_global_config["is_save_send_data_to_file"]:
            data_i = dbg.read(buf_i, len_i)
            util.save_buf_to_file("WSASendTo_%d" % i, data_i)

    params = {"buf_cnt": "%d" % buf_cnt, "size_sendto": "%.8X" % size}
    return retn_True(params)


def handler_WSARecv(dbg):
    """
        parse params

        ws2_32.WSARecv

          _In_    SOCKET                             s,
          _Inout_ LPWSABUF                           lpBuffers,
          _In_    DWORD                              dwBufferCount,
          _Out_   LPDWORD                            lpNumberOfBytesRecvd,
          _Inout_ LPDWORD                            lpFlags,
          _In_    LPWSAOVERLAPPED                    lpOverlapped,
          _In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    return retn_True()


def handler_WSARecvFrom(dbg):
    """
        parse params

        ws2_32.WSARecvFrom

          _In_    SOCKET                             s,
          _Inout_ LPWSABUF                           lpBuffers,
          _In_    DWORD                              dwBufferCount,
          _Out_   LPDWORD                            lpNumberOfBytesRecvd,
          _Inout_ LPDWORD                            lpFlags,
          _Out_   struct sockaddr                    *lpFrom,
          _Inout_ LPINT                              lpFromlen,
          _In_    LPWSAOVERLAPPED                    lpOverlapped,
          _In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    return retn_True()


def handler_InternetConnectA(dbg):
    """
        modify params

        wininet.InternetConnectA

        InternetConnectW-->InternetConnectA-->FtpConnect/HttpConnect

          _In_ HINTERNET     hInternet,
          _In_ LPCTSTR       lpszServerName,
          _In_ INTERNET_PORT nServerPort,
          _In_ LPCTSTR       lpszUsername,
          _In_ LPCTSTR       lpszPassword,
          _In_ DWORD         dwService,
          _In_ DWORD         dwFlags,
          _In_ DWORD_PTR     dwContext

          ParamLogCtrl(0x14, "user_pwd", V_PARAM_LOG_PASTR)]
    """
    svr = read_stack_p_ascii_string(dbg, 8)
    user_name = read_stack_p_ascii_string(dbg, 0x10)
    user_pwd = read_stack_p_ascii_string(dbg, 0x14)

    extrainfo = None
    if len(api_global_config["new_http_connect_url"]) != 0:
        write_stack_p_ascii_string(dbg, 8, api_global_config["new_http_connect_url"])
        extrainfo = ">>> new http connect svr: %s <<<" % api_global_config["new_http_connect_url"]

    params = {"svr": svr, "user_name": user_name, "user_pwd": user_pwd}
    return retn_True(params, extrainfo)


def handler_HttpSendRequestExA(dbg):
    """
        parse params

        wininet.HttpSendRequestExA

        HttpSendRequestExA-->HttpWrapSendRequest

          _In_  HINTERNET          hRequest,
          _In_  LPINTERNET_BUFFERS lpBuffersIn,
          _Out_ LPINTERNET_BUFFERS lpBuffersOut,
          _In_  DWORD              dwFlags,
          _In_  DWORD_PTR          dwContext
    """
    p_buf = read_stack_int32(dbg, 8)
    header, buf, len_ = parse_internetbuf(dbg, p_buf)

    params = {"header": header, "buf": "%.8X" % buf, "size_httpsend": "%.8X" % len_}
    return retn_True(params)


def handler_HttpSendRequestExW(dbg):
    """
        parse params

        wininet.HttpSendRequestExW

        HttpSendRequestExW-->HttpWrapSendRequest

          _In_  HINTERNET          hRequest,
          _In_  LPINTERNET_BUFFERS lpBuffersIn,
          _Out_ LPINTERNET_BUFFERS lpBuffersOut,
          _In_  DWORD              dwFlags,
          _In_  DWORD_PTR          dwContext
    """
    p_buf = read_stack_int32(dbg, 8)
    header, buf, len_ = parse_internetbuf(dbg, p_buf)

    params = {"header": header, "buf": "%.8X" % buf, "size_httpsend": "%.8X" % len_}
    return retn_True(params)


def handler_ret_WinHttpCreateUrl(dbg):
    """
        record result url
    """
    global callback_runtime
    assert "addr_result_WinHttpCreateUrl" in callback_runtime

    ret_url = read_unicode_string(dbg, callback_runtime["addr_result_WinHttpCreateUrl"])

    _xrk_api_invoke_retn_detail(dbg, "WinHttpCreateUrl", ret_dict={"ret_url": ret_url})

    del callback_runtime["addr_result_WinHttpCreateUrl"]

    assert "addr_WinHttpCreateUrl_rets" in callback_runtime and len(callback_runtime["addr_WinHttpCreateUrl_rets"]) == 8
    for ret_addr in callback_runtime["addr_WinHttpCreateUrl_rets"]:
        dbg.uninstall_hook_by_tid(ret_addr)

    return defines.DBG_CONTINUE


def handler_WinHttpCreateUrl(dbg):
    """
        record created url

        winhttp.WinHttpCreateUrl

        WinHttpCreateUrl-->winhttp.WinHttpCreateUrlA

          _In_    LPURL_COMPONENTS lpUrlComponents,
          _In_    DWORD            dwFlags,
          _Out_   LPWSTR           pwszUrl,
          _Inout_ LPDWORD          lpdwUrlLength
    """
    result_addr = read_stack_int32(dbg, 0xC)

    global callback_runtime
    assert "addr_result_WinHttpCreateUrl" not in callback_runtime

    callback_runtime["addr_result_WinHttpCreateUrl"] = result_addr

    # start: 00008DCA
    # retn:
    # 00008F21 - 0x157
    # 00008FEC - 0x222
    # 000090D7 - 0x30D
    # 000091C2 - 0x3F8
    # 000092AD - 0x4E3
    # 00009398 - 0x5CE
    # 00009483 - 0x6B9
    # 00009629 - 0x85F
    #
    offsets = [0x157, 0x222, 0x30D, 0x3F8, 0x4E3, 0x5CE, 0x6B9, 0x85F]
    assert "addr_WinHttpCreateUrl_rets" not in callback_runtime
    callback_runtime["addr_WinHttpCreateUrl_rets"] = []
    for offset in offsets:
        callback_runtime["addr_WinHttpCreateUrl_rets"].append(dbg.cur_eip() + offset)

    for ret_addr in callback_runtime["addr_WinHttpCreateUrl_rets"]:
        dbg.install_hook_by_tid(ret_addr, callback=handler_ret_WinHttpCreateUrl)

    return retn_True()


def handler_WinHttpWriteData(dbg):
    """
        check write buf header

        winhttp.WinHttpWriteData

        WinHttpWriteData-->CFsm_HttpWriteData::CFsm_HttpWriteData

          _In_  HINTERNET hRequest,
          _In_  LPCVOID   lpBuffer,
          _In_  DWORD     dwNumberOfBytesToWrite,
          _Out_ LPDWORD   lpdwNumberOfBytesWritten
    """
    buf = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0xC)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, buf, "WinHttpWriteData")

    params = {"buf": "%.8X" % buf, "size_httpwrite": "%.8X" % size}
    return retn_True(params, extrainfo)


def handler_IsWow64Process(dbg):
    """
        parse params

        kernel32.IsWow64Process

        IsWow64Process-->NtQueryInformationProcess(ntdll)

          _In_  HANDLE hProcess,
          _Out_ PBOOL  Wow64Process
    """
    h_proc = read_stack_int32(dbg, 4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    params = {"proc": h_proc_str}
    return retn_True(params)


def handler_ret_CreateProcessInternalW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_CreateProcessInternalW" in callback_runtime

    pid = read_int32(dbg, callback_runtime["addr_result_CreateProcessInternalW"] + 8)
    _xrk_api_invoke_retn_detail(dbg, "CreateProcessInternalW", ret_dict={"ret_pid": "%d" % pid})

    del callback_runtime["addr_result_CreateProcessInternalW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_CreateProcessInternalW(dbg):
    """
        parse params, record result

        kernel32.CreateProcessInternalW

        CreateProcessA-->CreateProcessInternalA-->CreateProcessInternalW
        CreateProcessW-->CreateProcessInternalW
        WinExec-->CreateProcessInternalA==>>||

          HANDLE hToken,
          LPCWSTR lpApplicationName,
          LPWSTR lpCommandLine,
          LPSECURITY_ATTRIBUTES lpProcessAttributes,
          LPSECURITY_ATTRIBUTES lpThreadAttributes,
          BOOL bInheritHandles,
          DWORD dwCreationFlags,
          LPVOID lpEnvironment,
          LPCWSTR lpCurrentDirectory,
          LPSTARTUPINFOW lpStartupInfo,
          LPPROCESS_INFORMATION lpProcessInformation,
          PHANDLE hNewToken
    """
    app_name = read_stack_p_unicode_string(dbg, 8)
    cmd_line = read_stack_p_unicode_string(dbg, 0xC)
    cur_dir_ = read_stack_p_unicode_string(dbg, 0x24)

    if app_name:
        _add_proc_to_proc_summary("%s %s" % (app_name, cmd_line))
    else:
        _add_proc_to_proc_summary(cmd_line)

    global callback_runtime
    assert "addr_result_CreateProcessInternalW" not in callback_runtime
    callback_runtime["addr_result_CreateProcessInternalW"] = read_stack_int32(dbg, 0x2C)
    # 0001A04D - 0001979C = 0x8B1
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x8B1, callback=handler_ret_CreateProcessInternalW)

    params = {"app_name": app_name, "cmd_line": cmd_line, "cur_dir": cur_dir_}
    return retn_True(params)


def handler_CreateRemoteThread(dbg):
    """
        check if create thread in debugee process

        kernel32.CreateRemoteThread

        CreateRemoteThread-->NtCreateThread(ntdll)
        CreateThread-->CreateRemoteThread==>>||

          _In_  HANDLE                 hProcess,
          _In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
          _In_  SIZE_T                 dwStackSize,
          _In_  LPTHREAD_START_ROUTINE lpStartAddress,
          _In_  LPVOID                 lpParameter,
          _In_  DWORD                  dwCreationFlags,
          _Out_ LPDWORD                lpThreadId
    """
    h_proc = read_stack_int32(dbg, 4)
    cbk = read_stack_int32(dbg, 0x10)

    if h_proc != 0xFFFFFFFF:

        h_proc_str = h_proc_to_proc_str(dbg, h_proc)
        params = {"proc": h_proc_str, "cbk": "%.8X" % cbk}
        return retn_True(params, ["create remote thread in another process!!"])

    else:
        params = {"cbk": "%.8X" % cbk}
        return retn_True(params)


def handler_OpenProcess(dbg):
    """
        parse params

        kernel32.OpenProcess

        OpenProcess-->NtOpenProcess(ntdll)

          _In_ DWORD dwDesiredAccess,
          _In_ BOOL  bInheritHandle,
          _In_ DWORD dwProcessId
    """
    pid = read_stack_int32(dbg, 0xC)
    proc_path = util.pid_to_proc_path(pid)

    params = {"pid": "%d" % pid, "proc": proc_path}
    return retn_True(params)


def handler_GetExitCodeProcess(dbg):
    """
        parse params

        kernel32.GetExitCodeProcess

        GetExitCodeProcess-->NtQueryInformationProcess(ntdll)

          _In_   HANDLE hProcess,
          _Out_  LPDWORD lpExitCode
    """
    h_proc = read_stack_int32(dbg, 4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    params = {"proc": h_proc_str}
    return retn_True(params)


def handler_SetThreadContext(dbg):
    """
        parse params
    """
    p_ctx = read_stack_int32(dbg, 8)
    flags, flags_str = parse_context(dbg, p_ctx)

    params = {"flags": "%.8X-%s" % (flags, flags_str)}
    return retn_True(params)


def handler_GetThreadContext(dbg):
    """
        parse params
    """
    p_ctx = read_stack_int32(dbg, 8)
    flags, flags_str = parse_context(dbg, p_ctx)

    params = {"flags": "%.8X-%s" % (flags, flags_str)}
    return retn_True(params)


def handler_CreateToolhelp32Snapshot(dbg):
    """
        parse params

        kernel32.CreateToolhelp32Snapshot

          _In_ DWORD dwFlags,
          _In_ DWORD th32ProcessID
    """
    flags = read_stack_int32(dbg, 4)
    pid = read_stack_int32(dbg, 8)
    if pid == 0:
        proc_path = "[debugee]"
    else:
        proc_path = "%d-%s" % (pid, util.pid_to_proc_path(pid))

    flags_str = ""

    if flags & 0x80000000:
        flags_str = flags_str + "|TH32CS_INHERIT"
    if flags & 0x00000001:
        flags_str = flags_str + "|TH32CS_SNAPHEAPLIST"
    if flags & 0x00000008:
        flags_str = flags_str + "|TH32CS_SNAPMODULE"
    if flags & 0x00000010:
        flags_str = flags_str + "|TH32CS_SNAPMODULE32"
    if flags & 0x00000002:
        flags_str = flags_str + "|TH32CS_SNAPPROCESS"
    if flags & 0x00000004:
        flags_str = flags_str + "|TH32CS_SNAPTHREAD"

    flags_str = flags_str.strip("|")

    params = {"flags": flags_str, "proc": proc_path}
    return retn_True(params)


def handler_ReadProcessMemory(dbg):
    """
        parse params

        kernel32.ReadProcessMemory

        ReadProcessMemory-->NtReadVirtualMemory(ntdll)
        Toolhelp32ReadProcessMemory-->OpenProcess/ReadProcessMemory

          _In_  HANDLE  hProcess,
          _In_  LPCVOID lpBaseAddress,
          _Out_ LPVOID  lpBuffer,
          _In_  SIZE_T  nSize,
          _Out_ SIZE_T  *lpNumberOfBytesRead
    """
    base = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0x10)
    h_proc = read_stack_int32(dbg, 4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    # todo: we might need to record results

    params = {"proc": h_proc_str, "base": "%.8X" % base, "size_read_from_proc": "%.8X" % size}
    return retn_True(params)


def handler_WriteProcessMemory(dbg):
    """
        check if buf has PE header

        kernel32.WriteProcessMemory

        WriteProcessMemory-->NtProtectVirtualMemory/NtWriteVirtualMemory(ntdll)

          _In_  HANDLE  hProcess,
          _In_  LPVOID  lpBaseAddress,
          _In_  LPCVOID lpBuffer,
          _In_  SIZE_T  nSize,
          _Out_ SIZE_T  *lpNumberOfBytesWritten
    """
    base = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0x10)
    h_proc = read_stack_int32(dbg, 4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, base, "WriteProcessMemory")

    params = {"proc": h_proc_str, "base": "%.8X" % base, "size_write_to_proc": "%.8X" % size}
    return retn_True(params, extrainfo)


def handler_CreateFileMappingW(dbg):
    """
        parse params

        kernel32.CreateFileMappingW

        CreateFileMappingA-->CreateFileMappingW-->NtCreateSection(ntdll)

          _In_     HANDLE                hFile,
          _In_opt_ LPSECURITY_ATTRIBUTES lpAttributes,
          _In_     DWORD                 flProtect,
          _In_     DWORD                 dwMaximumSizeHigh,
          _In_     DWORD                 dwMaximumSizeLow,
          _In_opt_ LPCTSTR               lpName
    """
    h_file = read_stack_int32(dbg, 4)
    if h_file == 0xFFFFFFFF:
        file_str = "[system_paging]"

    else:
        file_str = h_file_to_file_str(dbg, h_file)

    file_opt = read_stack_p_unicode_string(dbg, 0x18)

    params = {"file": file_str, "file_opt": file_opt}
    return retn_True(params)


def handler_UnmapViewOfFile(dbg):
    """
        check if buf has PE header

        kernel32.UnmapViewOfFile

        UnmapViewOfFile-->NtUnmapViewOfSection

          LPCVOID lpBaseAddress
    """
    addr = read_stack_int32(dbg, 4)

    extrainfo = _check_if_data_is_pe(dbg, addr, "UnmapViewOfFile")

    params = {"addr": "%.8X" % addr}
    return retn_True(params, extrainfo)


def handler_CreateFileW(dbg):
    """
        param params

        kernel32.CreateFileW

        CreateFileA-->CreateFileW-->NtCreateFile(ntdll)
        OpenFile-->CreateFileA==>||
        _lopen-->CreateFileA==>>||
        _lcreat-->CreateFileA==>>||

          _In_     LPCTSTR               lpFileName,
          _In_     DWORD                 dwDesiredAccess,
          _In_     DWORD                 dwShareMode,
          _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          _In_     DWORD                 dwCreationDisposition,
          _In_     DWORD                 dwFlagsAndAttributes,
          _In_opt_ HANDLE                hTemplateFile
    """
    file = read_stack_p_unicode_string(dbg, 4)
    # todo: parse these 2 params
    # access = read_stack_int32(dbg, 8)
    # mode = read_stack_int32(dbg, 0xC)

    params = {"file": file}
    return retn_True(params)


def handler_WriteFile(dbg):
    """
        check if buf has PE header

        kernel32.WriteFile

        WriteFile-->NtWriteFile(ntdll)
        _lwrite-->WriteFile==>>||

          HANDLE hFile,
          LPCVOID lpBuffer,
          DWORD nNumberOfBytesToWrite,
          LPDWORD lpNumberOfBytesWritten,
          LPOVERLAPPED lpOverlapped
    """
    buf = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0xC)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, buf, "WriteFile")

    params = {"buf": "%.8X" % buf, "size_write_file": "%.8X" % size}
    return retn_True(params, extrainfo)


def handler_WriteFileEx(dbg):
    """
        check if buf has PE header

        kernel32.WriteFileEx

        WriteFileEx-->NtWriteFile(ntdll)

          _In_     HANDLE                          hFile,
          _In_opt_ LPCVOID                         lpBuffer,
          _In_     DWORD                           nNumberOfBytesToWrite,
          _Inout_  LPOVERLAPPED                    lpOverlapped,
          _In_     LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    """
    buf = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0xC)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, buf, "WriteFileEx")

    params = {"buf": "%.8X" % buf, "size_write_file_ex": "%.8X" % size}
    return retn_True(params, extrainfo)


def handler_MoveFileWithProgressW(dbg):
    """
        parse params

        kernel32.MoveFileWithProgressW

        MoveFileA-->MoveFileWithProgressA-->MoveFileWithProgressW-->BasepCopyFileExW-->BaseCopyStream
        MoveFileW-->MoveFileWithProgressW==>||
        MoveFileExA-->MoveFileWithProgressA==>>||
        MoveFileExW-->MoveFileWithProgressW==>>||

          _In_     LPCTSTR            lpExistingFileName,
          _In_opt_ LPCTSTR            lpNewFileName,
          _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
          _In_opt_ LPVOID             lpData,
          _In_     DWORD              dwFlags

          MOVEFILE_COPY_ALLOWED          2  (0x2)
          MOVEFILE_CREATE_HARDLINK       16 (0x10)
          MOVEFILE_DELAY_UNTIL_REBOOT    4  (0x4)
          MOVEFILE_FAIL_IF_NOT_TRACKABLE 32 (0x20)
          MOVEFILE_REPLACE_EXISTING      1  (0x1)
          MOVEFILE_WRITE_THROUGH         8  (0x8)
    """
    file_old = read_stack_p_unicode_string(dbg, 4)
    file_new = read_stack_p_unicode_string(dbg, 8)
    flags = read_stack_int32(dbg, 0x14)

    flags_str = ""
    if flags & 0x1:
        flags_str = flags_str + "|MOVEFILE_REPLACE_EXISTING"
    if flags & 0x2:
        flags_str = flags_str + "|MOVEFILE_COPY_ALLOWED"
    if flags & 0x4:
        flags_str = flags_str + "|MOVEFILE_DELAY_UNTIL_REBOOT"
    if flags & 0x8:
        flags_str = flags_str + "|MOVEFILE_WRITE_THROUGH"
    if flags & 0x10:
        flags_str = flags_str + "|MOVEFILE_CREATE_HARDLINK"
    if flags & 0x20:
        flags_str = flags_str + "|MOVEFILE_FAIL_IF_NOT_TRACKABLE"

    flags_str = flags_str.strip("|")

    extrainfo = None
    if (file_new is None or len(file_new) == 0) and (flags == 0x4):
        extrainfo = "will del file when system reboot"

    params = {"file_old": file_old, "file_new": file_new, "flags": flags_str}
    return retn_True(params, extrainfo)


def handler_RemoveDirectoryW(dbg):
    """
        might backup dir

        kernel32.RemoveDirectoryW

        RemoveDirectoryA-->RemoveDirectoryW-->NtOpenFile/NtSetInformationFile(ntdll)

          LPCTSTR lpPathName
    """
    dir_ = read_stack_p_unicode_string(dbg, 4)

    if api_global_config["is_backup_remove_stuff"]:
        # 未实现
        pass

    params = {"dir": dir_}
    return retn_True(params)


def handler_ReplaceFileW(dbg):
    """
        backup file

        kernel32.ReplaceFileW

        ReplaceFileA-->ReplaceFileW-->NtOpenFile/NtSetInformationFile(ntdll)

          _In_       LPCTSTR lpReplacedFileName,
          _In_       LPCTSTR lpReplacementFileName,
          _In_opt_   LPCTSTR lpBackupFileName,
          _In_       DWORD   dwReplaceFlags,
          _Reserved_ LPVOID  lpExclude,
          _Reserved_ LPVOID  lpReserved
    """
    file_replaced = read_stack_p_unicode_string(dbg, 4)
    file_replacement = read_stack_p_unicode_string(dbg, 8)
    file_backup = read_stack_p_printable_string(dbg, 0xC)

    if api_global_config["is_backup_remove_stuff"]:
        # 未实现
        pass

    params = {"file_replaced": file_replaced, "file_replacement": file_replacement, "file_backup": file_backup}
    return retn_True(params)


def handler_DeleteFileW(dbg):
    """
        backup file

        kernel32.DeleteFileW

        DeleteFileA-->DeleteFileW-->NtOpenFile(ntdll)

          LPCTSTR lpFileName
    """
    file = read_stack_p_unicode_string(dbg, 4)

    if api_global_config["is_backup_remove_stuff"]:
        # 未实现
        pass

    params = {"file": file}
    return retn_True(params)


def handler_SetFileAttributesW(dbg):
    """
        parse attribute

        kernel32.SetFileAttributesW

        SetFileAttributesA-->SetFileAttributesW-->NtOpenFile/NtSetInformationFile(ntdll)

          LPCTSTR lpFileName,
          DWORD dwAttributes
    """
    file = read_stack_p_unicode_string(dbg, 4)

    attr = read_stack_int32(dbg, 8)

    attr_str = ""

    if attr & 0x1:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_READONLY"
    if attr & 0x2:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_HIDDEN"
    if attr & 0x4:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_SYSTEM"
    if attr & 0x10:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_DIRECTORY"
    if attr & 0x20:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_ARCHIVE"
    if attr & 0x40:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_DEVICE"
    if attr & 0x80:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_NORMAL"
    if attr & 0x100:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_TEMPORARY"
    if attr & 0x200:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_SPARSE_FILE"
    if attr & 0x400:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_REPARSE_POINT"
    if attr & 0x800:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_COMPRESSED"
    if attr & 0x1000:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_OFFLINE"
    if attr & 0x2000:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"
    if attr & 0x4000:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_ENCRYPTED"
    if attr & 0x8000:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_INTEGRITY_STREAM"
    if attr & 0x10000:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_VIRTUAL"
    if attr & 0x20000:
        attr_str = attr_str + "|" + "FILE_ATTRIBUTE_NO_SCRUB_DATA"

    if len(attr_str) == 0:
        attr_str = "FILE_ATTRIBUTE_NORMAL"
    else:
        attr_str = attr_str.strip("|")

    params = {"file": file, "attr_str": attr_str}
    return retn_True(params)


def handler_SetFileTime(dbg):
    """
        parse params

        kernel32.SetFileTime

        SetFileTime-->NtSetInformationFile

          _In_           HANDLE   hFile,
          _In_opt_ const FILETIME *lpCreationTime,
          _In_opt_ const FILETIME *lpLastAccessTime,
          _In_opt_ const FILETIME *lpLastWriteTime

        typedef struct _FILETIME {
          DWORD dwLowDateTime;
          DWORD dwHighDateTime;
        } FILETIME, *PFILETIME;
    """
    p_time_create = read_stack_int32(dbg, 8)
    p_time_last_access = read_stack_int32(dbg, 0xC)
    p_time_last_write = read_stack_int32(dbg, 0x10)

    time_create = ""
    time_last_access = ""
    time_last_write = ""

    if p_time_create != 0:
        time_create_block = _read_FILETIME(dbg, p_time_create)
        time_create = _file_time_to_sys_time_param_str(time_create_block)

    if p_time_last_access != 0:
        time_last_access_block = _read_FILETIME(dbg, p_time_last_access)
        time_last_access = _file_time_to_sys_time_param_str(time_last_access_block)

    if p_time_last_write != 0:
        time_last_write_block = _read_FILETIME(dbg, p_time_last_write)
        time_last_write = _file_time_to_sys_time_param_str(time_last_write_block)

    params = {"time_create": time_create, "time_last_access": time_last_access, "time_last_write": time_last_write}
    return retn_True(params)


def handler_ret_GetTempPathW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetTempPathW" in callback_runtime

    result_str = dbg.read_unicode_string(callback_runtime["addr_result_GetTempPathW"])
    _xrk_api_invoke_retn_detail(dbg, "GetTempPathW", ret_dict={"ret_path": result_str})

    del callback_runtime["addr_result_GetTempPathW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetTempPathW(dbg):
    """
        record result

        kernel32.GetTempPathW

        GetTempPathA-->GetTempPathW-->BasepGetTempPathW-->RtlQueryEnvironmentVariable_U

          _In_  DWORD  nBufferLength,
          _Out_ LPTSTR lpBuffer
    """
    global callback_runtime
    assert "addr_result_GetTempPathW" not in callback_runtime

    callback_runtime["addr_result_GetTempPathW"] = read_stack_int32(dbg, 8)
    # 0003078C - 00030779 = 0x13
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x13, callback=handler_ret_GetTempPathW)

    return retn_True()


def handler_ret_GetTempFileNameW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetTempFileNameW" in callback_runtime

    result_str = dbg.read_unicode_string(callback_runtime["addr_result_GetTempFileNameW"])
    _xrk_api_invoke_retn_detail(dbg, "GetTempFileNameW", ret_dict={"ret_name": result_str})

    del callback_runtime["addr_result_GetTempFileNameW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetTempFileNameW(dbg):
    """
        record result
    """
    path = read_stack_p_unicode_string(dbg, 4)
    prefix = read_stack_p_unicode_string(dbg, 8)
    result_addr = read_stack_int32(dbg, 0x10)

    global callback_runtime
    assert "addr_result_GetTempFileNameW" not in callback_runtime
    callback_runtime["addr_result_GetTempFileNameW"] = result_addr
    # 00035BAE - 000359CF = 0x1DF
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x1DF, callback=handler_ret_GetTempFileNameW)

    params = {"path": path, "prefix": prefix}
    return retn_True(params)


def handler_ret_GetSystemDirectoryA(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetSystemDirectoryA" in callback_runtime

    result_str = dbg.read_ascii_string(callback_runtime["addr_result_GetSystemDirectoryA"])
    _xrk_api_invoke_retn_detail(dbg, "GetSystemDirectoryA", ret_dict={"sys_dir": result_str})

    del callback_runtime["addr_result_GetSystemDirectoryA"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetSystemDirectoryA(dbg):
    """
        record result

        kernel32.GetSystemDirectoryA

        GetSystemDirectoryA-->BaseWindowsSystemDirectory/RtlUnicodeToMultiByteSize/xx

          _Out_ LPTSTR lpBuffer,
          _In_  UINT   uSize
    """
    global callback_runtime
    assert "addr_result_GetSystemDirectoryA" not in callback_runtime

    # # for now, we don't need to modify result.
    # callback_runtime["addr_result_GetSystemDirectoryA"] = read_stack_int32(dbg, 4)
    # # 00014FD8 - 00014F7A = 0x5E
    # dbg.install_hook_by_tid(dbg.cur_eip() + 0x5E, callback=handler_ret_GetSystemDirectoryA)

    return retn_True()


def handler_ret_GetSystemDirectoryW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetSystemDirectoryW" in callback_runtime

    result_str = dbg.read_unicode_string(callback_runtime["addr_result_GetSystemDirectoryW"])
    _xrk_api_invoke_retn_detail(dbg, "GetSystemDirectoryW", ret_dict={"sys_dir": result_str})

    del callback_runtime["addr_result_GetSystemDirectoryW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetSystemDirectoryW(dbg):
    """
        record result

        kernel32.GetSystemDirectoryW

        GetSystemDirectoryW-->BaseWindowsSystemDirectory

          _Out_ LPTSTR lpBuffer,
          _In_  UINT   uSize
    """
    global callback_runtime
    assert "addr_result_GetSystemDirectoryW" not in callback_runtime

    # # for now, we don't need to modify result.
    # callback_runtime["addr_result_GetSystemDirectoryW"] = read_stack_int32(dbg, 4)
    # # 00031E24 - 00031DD3 = 0x51
    # dbg.install_hook_by_tid(dbg.cur_eip() + 0x51, callback=handler_ret_GetSystemDirectoryW)

    return retn_True()


def handler_ret_GetFullPathNameW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetFullPathNameW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_GetFullPathNameW"])
    _xrk_api_invoke_retn_detail(dbg, "GetFullPathNameW", ret_dict={"ret_path": result_str})

    del callback_runtime["addr_result_GetFullPathNameW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetFullPathNameW(dbg):
    """
        record result

        kernel32.GetFullPathNameW

        GetVolumePathNameA-->GetVolumePathNameW-->GetFullPathNameW

          _In_  LPCTSTR lpFileName,
          _In_  DWORD   nBufferLength,
          _Out_ LPTSTR  lpBuffer,
          _Out_ LPTSTR  *lpFilePart
    """
    file = read_stack_p_unicode_string(dbg, 4)
    result_addr = read_stack_int32(dbg, 0xC)

    global callback_runtime
    assert "addr_result_GetFullPathNameW" not in callback_runtime

    callback_runtime["addr_result_GetFullPathNameW"] = result_addr

    # 0000B8FF - 0000B8E2 = 0x1D
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x1D, callback=handler_ret_GetFullPathNameW)

    params = {"file": file}
    return retn_True(params)


def handler_CreateServiceA(dbg):
    """
        parse params

        advapi32.CreateServiceA

        CreateServiceA-->RCreateServiceA

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpServiceName,
          _In_opt_  LPCTSTR   lpDisplayName,
          _In_      DWORD     dwDesiredAccess,
          _In_      DWORD     dwServiceType,
          _In_      DWORD     dwStartType,
          _In_      DWORD     dwErrorControl,
          _In_opt_  LPCTSTR   lpBinaryPathName,
          _In_opt_  LPCTSTR   lpLoadOrderGroup,
          _Out_opt_ LPDWORD   lpdwTagId,
          _In_opt_  LPCTSTR   lpDependencies,
          _In_opt_  LPCTSTR   lpServiceStartName,
          _In_opt_  LPCTSTR   lpPassword
    """
    name_svc = read_stack_p_ascii_string(dbg, 8)
    name_display = read_stack_p_ascii_string(dbg, 0xC)
    svc_type = read_stack_int32(dbg, 0x14)
    start_type = read_stack_int32(dbg, 0x18)
    error_ctrl = read_stack_int32(dbg, 0x1C)
    bin_path = read_stack_p_ascii_string(dbg, 0x20)
    load_order_group = read_stack_p_ascii_string(dbg, 0x24)

    svc_type_str = svc_type_to_str(svc_type)
    start_type_str = start_type_to_str(start_type)
    error_str = error_ctrl_to_str(error_ctrl)

    params = {"name": name_svc, "display": name_display, "svc_type": svc_type_str, "start_type": start_type_str,
              "error": error_str, "file_bin": bin_path, "load_order_group": load_order_group}
    return retn_True(params)


def handler_CreateServiceW(dbg):
    """
        parse params

        advapi32.CreateServiceW

        CreateServiceW-->RCreateServiceW

          _In_      SC_HANDLE hSCManager,
          _In_      LPCTSTR   lpServiceName,
          _In_opt_  LPCTSTR   lpDisplayName,
          _In_      DWORD     dwDesiredAccess,
          _In_      DWORD     dwServiceType,
          _In_      DWORD     dwStartType,
          _In_      DWORD     dwErrorControl,
          _In_opt_  LPCTSTR   lpBinaryPathName,
          _In_opt_  LPCTSTR   lpLoadOrderGroup,
          _Out_opt_ LPDWORD   lpdwTagId,
          _In_opt_  LPCTSTR   lpDependencies,
          _In_opt_  LPCTSTR   lpServiceStartName,
          _In_opt_  LPCTSTR   lpPassword
    """
    name_svc = read_stack_p_unicode_string(dbg, 8)
    name_display = read_stack_p_unicode_string(dbg, 0xC)
    svc_type = read_stack_int32(dbg, 0x14)
    start_type = read_stack_int32(dbg, 0x18)
    error_ctrl = read_stack_int32(dbg, 0x1C)
    bin_path = read_stack_p_unicode_string(dbg, 0x20)
    load_order_group = read_stack_p_unicode_string(dbg, 0x24)

    svc_type_str = svc_type_to_str(svc_type)
    start_type_str = start_type_to_str(start_type)
    error_str = error_ctrl_to_str(error_ctrl)

    params = {"name": name_svc, "display": name_display, "svc_type": svc_type_str, "start_type": start_type_str,
              "error": error_str, "file_bin": bin_path, "load_order_group": load_order_group}
    return retn_True(params)


def handler_ControlService(dbg):
    """
        parse params

        advapi32.ControlService

        ControlService-->RControlService

          _In_  SC_HANDLE        hService,
          _In_  DWORD            dwControl,
          _Out_ LPSERVICE_STATUS lpServiceStatus
    """
    code = read_stack_int32(dbg, 8)

    svc_ctrl_code_to_type = {
        0x1: "SERVICE_CONTROL_STOP",
        0x2: "SERVICE_CONTROL_PAUSE",
        0x3: "SERVICE_CONTROL_CONTINUE",
        0x4: "SERVICE_CONTROL_INTERROGATE",
        0x6: "SERVICE_CONTROL_PARAMCHANGE",
        0x7: "SERVICE_CONTROL_NETBINDADD",
        0x8: "SERVICE_CONTROL_NETBINDREMOVE",
        0x9: "SERVICE_CONTROL_NETBINDENABLE",
        0xA: "SERVICE_CONTROL_NETBINDDISABLE"
    }

    if code in svc_ctrl_code_to_type:
        code_str = svc_ctrl_code_to_type[code]
    else:
        code_str = "%d(Unknown)" % code

    params = {"code": code_str}
    if code == 0x1:
        return retn_True(params, ["pay attention: sample might stop svc then replace binary by setting reg then start svc again."])
    else:
        return retn_True(params)
    return params


def handler_StartServiceCtrlDispatcherA(dbg):
    """
        parse param

        advapi32.StartServiceCtrlDispatcherA

          _In_  const SERVICE_TABLE_ENTRY *lpServiceTable

        typedef struct _SERVICE_TABLE_ENTRY {
          LPTSTR                  lpServiceName;
          LPSERVICE_MAIN_FUNCTION lpServiceProc;
        } SERVICE_TABLE_ENTRY, *LPSERVICE_TABLE_ENTRY;
    """
    ptable = read_stack_int32(dbg, 4)
    svc_name = read_ascii_string(dbg, ptable)
    cbk = read_int32(dbg, ptable + 4)

    params = {"svc": svc_name, "cbk": cbk}
    return retn_True(params)


def handler_StartServiceCtrlDispatcherW(dbg):
    """
        parse param

        advapi32.StartServiceCtrlDispatcherW

          _In_  const SERVICE_TABLE_ENTRY *lpServiceTable

        typedef struct _SERVICE_TABLE_ENTRY {
          LPTSTR                  lpServiceName;
          LPSERVICE_MAIN_FUNCTION lpServiceProc;
        } SERVICE_TABLE_ENTRY, *LPSERVICE_TABLE_ENTRY;
    """
    ptable = read_stack_int32(dbg, 4)
    svc_name = read_unicode_string(dbg, ptable)
    cbk = read_int32(dbg, ptable + 4)

    params = {"svc": svc_name, "cbk": cbk}
    return retn_True(params)


def handler_MessageBoxIndirectA(dbg):
    """
        parse msgbox info

        user32.MessageBoxIndirectA

        MessageBoxIndirectA-->MessageBoxWorker

          _In_ const LPMSGBOXPARAMS lpMsgBoxParams
    """
    p_params = read_stack_int32(dbg, 4)
    txt, caption, style_str, fn_cbk = parse_msgbox_params(dbg, p_params)

    params = {"txt": txt, "caption": caption, "style": style_str, "cbk": "%.8X" % fn_cbk}
    return retn_True(params)


def handler_MessageBoxIndirectW(dbg):
    """
        parse msgbox info

        user32.MessageBoxIndirectW

        MessageBoxIndirectW-->MessageBoxWorker

          _In_ const LPMSGBOXPARAMS lpMsgBoxParams
    """
    p_params = read_stack_int32(dbg, 4)
    txt, caption, style_str, fn_cbk = parse_msgbox_params(dbg, p_params)

    params = {"txt": txt, "caption": caption, "style": style_str, "cbk": "%.8X" % fn_cbk}
    return retn_True(params)


def parse_winclass_params(dbg, p_class):
    """
        typedef struct tagWNDCLASS {
          UINT      style;
          WNDPROC   lpfnWndProc;
          int       cbClsExtra;
          int       cbWndExtra;
          HINSTANCE hInstance;
          HICON     hIcon;
          HCURSOR   hCursor;
          HBRUSH    hbrBackground;
          LPCTSTR   lpszMenuName;
          LPCTSTR   lpszClassName;
        } WNDCLASS, *PWNDCLASS;

        @return: TUPLE: (fn_cbk, menu_name, class_name)
    """
    fn_cbk = read_int32(dbg, p_class + 0x4)
    menu_name = read_p_ascii_string(dbg, p_class + 0x20)
    class_name = read_p_ascii_string(dbg, p_class + 0x24)

    return (fn_cbk, menu_name, class_name)


def handler_RegisterClassA(dbg):
    """
        parse class info

        user32.RegisterClassA

        RegisterClassA-->RegisterClassExWOWA-->NtUserRegisterClassExWOW

          _In_ const WNDCLASS *lpWndClass
    """
    p_class = read_stack_int32(dbg, 4)
    fn_cbk, menu_name, class_name = parse_winclass_params(dbg, p_class)

    params = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    return retn_True(params)


def handler_RegisterClassW(dbg):
    """
        parse class info

        user32.RegisterClassW

        RegisterClassW-->RegisterClassExWOWW-->NtUserRegisterClassExWOW

          _In_ const WNDCLASS *lpWndClass
    """
    p_class = read_stack_int32(dbg, 4)
    fn_cbk, menu_name, class_name = parse_winclass_params(dbg, p_class)

    params = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    return retn_True(params)


def parse_winclassex_params(dbg, p_class):
    """
        typedef struct tagWNDCLASSEX {
          UINT      cbSize;
          UINT      style;
          WNDPROC   lpfnWndProc;
          int       cbClsExtra;
          int       cbWndExtra;
          HINSTANCE hInstance;
          HICON     hIcon;
          HCURSOR   hCursor;
          HBRUSH    hbrBackground;
          LPCTSTR   lpszMenuName;
          LPCTSTR   lpszClassName;
          HICON     hIconSm;
        } WNDCLASSEX, *PWNDCLASSEX;

        @return: TUPLE: (fn_cbk, menu_name, class_name)
    """
    fn_cbk = read_int32(dbg, p_class + 0x8)
    menu_name = read_p_ascii_string(dbg, p_class + 0x24)
    class_name = read_p_ascii_string(dbg, p_class + 0x28)

    return (fn_cbk, menu_name, class_name)


def handler_RegisterClassExA(dbg):
    """
        parse class info

        user32.RegisterClassExA

        RegisterClassExA-->RegisterClassExWOWA=>>||

          _In_ const WNDCLASSEX *lpwcx
    """
    p_class = read_stack_int32(dbg, 4)
    fn_cbk, menu_name, class_name = parse_winclassex_params(dbg, p_class)

    params = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    return retn_True(params)


def handler_RegisterClassExW(dbg):
    """
        parse class info

        user32.RegisterClassExW

        RegisterClassExW-->RegisterClassExWOWW==>>||

          _In_ const WNDCLASSEX *lpwcx
    """
    p_class = read_stack_int32(dbg, 4)
    fn_cbk, menu_name, class_name = parse_winclassex_params(dbg, p_class)

    params = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    return retn_True(params)


def handler_DispatchMessageA(dbg):
    """
        parse param

        user32.DispatchMessageA

        DispatchMessageA-->DispatchMessageWorker

          _In_ const MSG *lpmsg
    """
    p_msg = read_stack_int32(dbg, 4)
    code = parse_msg_params(dbg, p_msg)

    params = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    return retn_True(params)


def handler_DispatchMessageW(dbg):
    """
        parse param

        user32.DispatchMessageW

        DispatchMessageW-->DispatchMessageWorker

          _In_ const MSG *lpmsg
    """
    p_msg = read_stack_int32(dbg, 4)
    code = parse_msg_params(dbg, p_msg)

    params = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    return retn_True(params)


def handler_PostMessageA(dbg):
    """
        resolve code

        user32.PostMessageA

        PostMessageA-->SendMessageA/NtUserPostMessage

          _In_opt_ HWND   hWnd,
          _In_     UINT   Msg,
          _In_     WPARAM wParam,
          _In_     LPARAM lParam
    """
    code = read_stack_int32(dbg, 8)

    params = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    return retn_True(params)


def handler_PostMessageW(dbg):
    """
        resolve code

        user32.PostMessageW

        PostMessageW-->SendMessageW/NtUserPostMessage

          _In_opt_ HWND   hWnd,
          _In_     UINT   Msg,
          _In_     WPARAM wParam,
          _In_     LPARAM lParam
    """
    code = read_stack_int32(dbg, 8)

    params = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    return retn_True(params)


def handler_SendMessageA(dbg):
    """
        resolve code

        user32.SendMessageA

        SendMessageA-->SendMessageWorker/gapfnScSendMessage/NtUserMessageCall

          _In_ HWND   hWnd,
          _In_ UINT   Msg,
          _In_ WPARAM wParam,
          _In_ LPARAM lParam
    """
    code = read_stack_int32(dbg, 8)

    params = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    return retn_True(params)


def handler_SendMessageW(dbg):
    """
        resolve code

        user32.SendMessageW

        SendMessageW-->SendMessageWorker/gapfnScSendMessage/NtUserMessageCall

          _In_ HWND   hWnd,
          _In_ UINT   Msg,
          _In_ WPARAM wParam,
          _In_ LPARAM lParam
    """
    code = read_stack_int32(dbg, 8)

    params = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    return retn_True(params)


def handler_FindResourceA(dbg):
    """
        parse params

        kernel32.FindResourceA

        FindResourceA-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpName,
          _In_     LPCTSTR lpType
    """
    name = read_stack_p_ascii_string(dbg, 8)
    if name is None or len(name) == 0:
        name = "%d(id)" % read_stack_int32(dbg, 8)
    type_ = read_stack_p_ascii_string(dbg, 0xC)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % read_stack_int32(dbg, 0xC)

    params = {"name": name, "type": type_}
    return retn_True(params)


def handler_FindResourceW(dbg):
    """
        parse params

        kernel32.FindResourceW

        FindResourceW-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpName,
          _In_     LPCTSTR lpType
    """
    name = read_stack_p_unicode_string(dbg, 8)
    if name is None or len(name) == 0:
        name = "%d(id)" % read_stack_int32(dbg, 8)
    type_ = read_stack_p_unicode_string(dbg, 0xC)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % read_stack_int32(dbg, 0xC)

    params = {"name": name, "type": type_}
    return retn_True(params)


def handler_FindResourceExA(dbg):
    """
        parse params

        kernel32.FindResourceExA

        FindResourceExA-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpType,
          _In_     LPCTSTR lpName,
          _In_     WORD    wLanguage
    """
    type_ = read_stack_p_ascii_string(dbg, 8)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % read_stack_int32(dbg, 8)
    name = read_stack_p_ascii_string(dbg, 0xC)
    if name is None or len(name) == 0:
        name = "%d(id)" % read_stack_int32(dbg, 0xC)

    params = {"name": name, "type": type_}
    return retn_True(params)


def handler_FindResourceExW(dbg):
    """
        parse params

        kernel32.FindResourceExW

        FindResourceExW-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpType,
          _In_     LPCTSTR lpName,
          _In_     WORD    wLanguage
    """
    type_ = read_stack_p_unicode_string(dbg, 8)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % read_stack_int32(dbg, 8)
    name = read_stack_p_unicode_string(dbg, 0xC)
    if name is None or len(name) == 0:
        name = "%d(id)" % read_stack_int32(dbg, 0xC)

    params = {"name": name, "type": type_}
    return retn_True(params)


def handler_ret_CreateMutexW(dbg):
    """
        change ret result
    """
    if dbg.context.Eax == 0:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "CreateMutexW", extrainfo="modify ret from 0 to 1")
            dbg.set_register("EAX", 1)

        else:
            _xrk_api_invoke_retn_detail(dbg, "CreateMutexW", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_CreateMutexW(dbg):
    """
        might change ret result

        kernel32.CreateMutexW

        CreateMutexA-->CreateMutexW-->NtCreateMutant(ntdll)

          _In_opt_ LPSECURITY_ATTRIBUTES lpMutexAttributes,
          _In_     BOOL                  bInitialOwner,
          _In_opt_ LPCTSTR               lpName
    """
    mutex = read_stack_p_unicode_string(dbg, 0xC)

    if api_global_config["is_all_mutex_check_success"] or \
       (len(api_global_config["success_mutex_name_list"]) != 0 and mutex in api_global_config["success_mutex_name_list"]):

        # set bp to modify ret of CreateMutexW
        # ret_offset: 0x0000E9C7 - 0x0000E947 = 0x80
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x80, callback=handler_ret_CreateMutexW)

        # modify ret of GetLastError
        _set_GetLastError_ret_once(dbg, 0)

    params = {"mutex": mutex}
    return retn_True(params)


def handler_OpenMutexW(dbg):
    """
        might change ret result

        kernel32.OpenMutexW

        OpenMutexA-->OpenMutexW-->NtOpenMutant(ntdll)

          _In_ DWORD   dwDesiredAccess,
          _In_ BOOL    bInheritHandle,
          _In_ LPCTSTR lpName
    """
    mutex = read_stack_p_unicode_string(dbg, 0xC)

    extrainfo = None
    if api_global_config["is_all_mutex_check_success"] or \
            (api_global_config["success_mutex_name_list"] and mutex in api_global_config["success_mutex_name_list"]):

        extrainfo = "some interesting mutex name appears, u should pay attention to this"

    params = {"mutex": mutex}
    return retn_True(params, extrainfo)


def handler_ret_access(dbg):
    """
        modify result
    """
    assert api_global_config["is_all_access_success"] is True

    if dbg.context.Eax == 0xFFFFFFFF:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "access", extrainfo="force ret from 0xFFFFFFFF to 0")
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "access", extrainfo="intrude debugee not allowed, so we cancel it.")

    global callback_runtime
    assert callback_runtime["addr_access_rets"] and len(callback_runtime["addr_access_rets"]) != 0
    for ret_addr in callback_runtime["addr_access_rets"]:
        dbg.uninstall_hook_by_tid(ret_addr)

    return defines.DBG_CONTINUE


def handler_access(dbg):
    """
        might change ret result
    """
    path = read_stack_p_ascii_string(dbg, 4)
    mode = read_stack_int32(dbg, 8)

    mode_str = ""
    if mode & 2:
        mode_str = mode_str + "|Write-only"
    if mode & 4:
        mode_str = mode_str + "|Read-only"
    if mode & 6:
        mode_str = mode_str + "|Read-write"
    mode_str = mode_str.strip("|")

    if len(mode_str) == 0:
        mode_str = "Existence-only"
    else:
        mode_str = mode_str.strip("|")

    if api_global_config["is_all_access_success"]:
        # start: 0000F355
        # tails:
        # 0000F379 - 0x24
        # 0000F39F - 0x4A
        offsets = [0x24, 0x4A]
        global callback_runtime
        if "addr_access_rets" not in callback_runtime:
            callback_runtime["addr_access_rets"] = []
            for offset in offsets:
                callback_runtime["addr_access_rets"].append(dbg.cur_eip() + offset)

        for ret_addr in callback_runtime["addr_access_rets"]:
            dbg.install_hook_by_tid(ret_addr, callback=handler_ret_access)

    params = {"path": path, "mode": mode_str}
    return retn_True(params)


def handler_IsProcessorFeaturePresent(dbg):
    """
        parse params
    """
    feature = read_stack_int32(dbg, 4)
    feature_dict = {
        0: "PF_FLOATING_POINT_PRECISION_ERRATA",
        1: "PF_FLOATING_POINT_EMULATED",
        2: "PF_COMPARE_EXCHANGE_DOUBLE",
        3: "PF_MMX_INSTRUCTIONS_AVAILABLE",
        4: "PF_PPC_MOVEMEM_64BIT_OK",
        5: "PF_ALPHA_BYTE_INSTRUCTIONS",
        6: "PF_XMMI_INSTRUCTIONS_AVAILABLE",
        7: "PF_3DNOW_INSTRUCTIONS_AVAILABLE",
        8: "PF_RDTSC_INSTRUCTION_AVAILABLE",
        9: "PF_PAE_ENABLED",
        10: "PF_XMMI64_INSTRUCTIONS_AVAILABLE",
        11: "PF_SSE_DAZ_MODE_AVAILABLE",
        12: "PF_NX_ENABLED",
        13: "PF_SSE3_INSTRUCTIONS_AVAILABLE",
        14: "PF_COMPARE_EXCHANGE128",
        15: "PF_COMPARE64_EXCHANGE128",
        16: "PF_CHANNELS_ENABLED",
        17: "PF_XSAVE_ENABLED"}

    if feature in feature_dict:
        feature_str = feature_dict[feature]
    else:
        feature_str = "None"

    params = {"feature": "%d-%s" % (feature, feature_str)}
    return retn_True(params)


def handler_NtQueryInformationProcess(dbg):
    """
        parse params
    """
    class_ = read_stack_int32(dbg, 8)

    class_dict = {
        0: "ProcessBasicInformation",
        1: "ProcessQuotaLimits",
        2: "ProcessIoCounters",
        3: "ProcessVmCounters",
        4: "ProcessTimes",
        5: "ProcessBasePriority",
        6: "ProcessRaisePriority",
        7: "ProcessDebugPort",
        8: "ProcessExceptionPort",
        9: "ProcessAccessToken",
        10: "ProcessLdtInformation",
        11: "ProcessLdtSize",
        12: "ProcessDefaultHardErrorMode",
        13: "ProcessIoPortHandlers",
        14: "ProcessPooledUsageAndLimits",
        15: "ProcessWorkingSetWatch",
        16: "ProcessUserModeIOPL",
        17: "ProcessEnableAlignmentFaultFixup",
        18: "ProcessPriorityClass",
        19: "ProcessWx86Information",
        20: "ProcessHandleCount",
        21: "ProcessAffinityMask",
        22: "ProcessPriorityBoost",
        23: "ProcessDeviceMap",
        24: "ProcessSessionInformation",
        25: "ProcessForegroundInformation",
        26: "ProcessWow64Information",
        27: "ProcessImageFileName",
        28: "ProcessLUIDDeviceMapsEnabled",
        29: "ProcessBreakOnTermination",
        30: "ProcessDebugObjectHandle",
        31: "ProcessDebugFlags",
        32: "ProcessHandleTracing",
        33: "ProcessIoPriority",
        34: "ProcessExecuteFlags",
        35: "ProcessResourceManagement",
        36: "ProcessCookie",
        37: "ProcessImageInformation",
        38: "ProcessCycleTime",
        39: "ProcessPagePriority",
        40: "ProcessInstrumentationCallback",
        41: "ProcessThreadStackAllocation",
        42: "ProcessWorkingSetWatchEx",
        43: "ProcessImageFileNameWin32",
        44: "ProcessImageFileMapping",
        45: "ProcessAffinityUpdateMode",
        46: "ProcessMemoryAllocationMode",
        47: "ProcessGroupInformation",
        48: "ProcessTokenVirtualizationEnabled",
        49: "ProcessConsoleHostProcess",
        50: "ProcessWindowInformation",
        51: "ProcessHandleInformation",
        52: "ProcessMitigationPolicy",
        53: "ProcessDynamicFunctionTableInformation",
        54: "ProcessHandleCheckingMode",
        55: "ProcessKeepAliveCount",
        56: "ProcessRevokeFileHandles",
        57: "ProcessWorkingSetControl",
        58: "ProcessHandleTable",
        59: "ProcessCheckStackExtentsMode",
        60: "ProcessCommandLineInformation",
        61: "ProcessProtectionInformation",
        62: "ProcessMemoryExhaustion",
        63: "ProcessFaultInformation",
        64: "ProcessTelemetryIdInformation",
        65: "ProcessCommitReleaseInformation",
        66: "ProcessDefaultCpuSetsInformation",
        67: "ProcessAllowedCpuSetsInformation",
        68: "ProcessReserved1Information",
        69: "ProcessReserved2Information",
        70: "ProcessSubsystemProcess",
        71: "ProcessJobMemoryInformation",
    }
    if class_ in class_dict:
        class_str = class_dict[class_]
    else:
        class_str = "None"

    params = {"class": "%d-%s" % (class_, class_str)}
    return retn_True(params)


def handler_NtQueryInformationThread(dbg):
    """
        parse params
    """
    class_ = read_stack_int32(dbg, 8)

    class_dict = {
        0: "ThreadBasicInformation",
        1: "ThreadTimes",
        2: "ThreadPriority",
        3: "ThreadBasePriority",
        4: "ThreadAffinityMask",
        5: "ThreadImpersonationToken",
        6: "ThreadDescriptorTableEntry",
        7: "ThreadEnableAlignmentFaultFixup",
        8: "ThreadEventPair_Reusable",
        9: "ThreadQuerySetWin32StartAddress",
        10: "ThreadZeroTlsCell",
        11: "ThreadPerformanceCount",
        12: "ThreadAmILastThread",
        13: "ThreadIdealProcessor",
        14: "ThreadPriorityBoost",
        15: "ThreadSetTlsArrayAddress",
        16: "ThreadIsIoPending",
        17: "ThreadHideFromDebugger",
        18: "ThreadBreakOnTermination",
        19: "ThreadSwitchLegacyState",
        20: "ThreadIsTerminated",
        21: "ThreadLastSystemCall",
        22: "ThreadIoPriority",
        23: "ThreadCycleTime",
        24: "ThreadPagePriority",
        25: "ThreadActualBasePriority",
        26: "ThreadTebInformation",
        27: "ThreadCSwitchMon",
        28: "ThreadCSwitchPmu",
        29: "ThreadWow64Context",
        30: "ThreadGroupInformation",
        31: "ThreadUmsInformation",
        32: "ThreadCounterProfiling",
        33: "ThreadIdealProcessorEx",
        34: "ThreadCpuAccountingInformation",
        35: "ThreadSuspendCount",
        41: "ThreadActualGroupAffinity",
        42: "ThreadDynamicCodePolicy",
    }
    if class_ in class_dict:
        class_str = class_dict[class_]
    else:
        class_str = "None"

    params = {"class": "%d-%s" % (class_, class_str)}
    return retn_True(params)


def handler_NtSetInformationProcess(dbg):
    """
        parse params
    """
    return {}


def handler_ret_ExpandEnvironmentStringsA(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_ExpandEnvironmentStringsA" in callback_runtime

    result_str = read_ascii_string(dbg, callback_runtime["addr_result_ExpandEnvironmentStringsA"])
    _xrk_api_invoke_retn_detail(dbg, "ExpandEnvironmentStringsA", ret_dict={"ret_str": result_str})

    del callback_runtime["addr_result_ExpandEnvironmentStringsA"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_ExpandEnvironmentStringsA(dbg):
    """
        record result

        kernel32.ExpandEnvironmentStringsA

        ExpandEnvironmentStringsA-->RtlExpandEnvironmentStrings_U(ntdll)

          _In_      LPCTSTR lpSrc,
          _Out_opt_ LPTSTR  lpDst,
          _In_      DWORD   nSize
    """
    src = read_stack_p_ascii_string(dbg, 4)
    result_addr = read_stack_int32(dbg, 8)

    global callback_runtime
    assert "addr_result_ExpandEnvironmentStringsA" not in callback_runtime
    callback_runtime["addr_result_ExpandEnvironmentStringsA"] = result_addr

    # 00032AEB - 000329F1 = 0xFA
    dbg.install_hook_by_tid(dbg.cur_eip() + 0xFA, callback=handler_ret_ExpandEnvironmentStringsA)

    params = {"src": src}
    return retn_True(params)


def handler_ret_ExpandEnvironmentStringsW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_ExpandEnvironmentStringsW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_ExpandEnvironmentStringsW"])
    _xrk_api_invoke_retn_detail(dbg, "ExpandEnvironmentStringsW", ret_dict={"ret_str": result_str})

    del callback_runtime["addr_result_ExpandEnvironmentStringsW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_ExpandEnvironmentStringsW(dbg):
    """
        record result

        kernel32.ExpandEnvironmentStringsW

        ExpandEnvironmentStringsW-->RtlExpandEnvironmentStrings_U(ntdll)

          _In_      LPCTSTR lpSrc,
          _Out_opt_ LPTSTR  lpDst,
          _In_      DWORD   nSize
    """
    src = read_stack_p_unicode_string(dbg, 4)
    result_addr = read_stack_int32(dbg, 8)

    global callback_runtime
    assert "addr_result_ExpandEnvironmentStringsW" not in callback_runtime
    callback_runtime["addr_result_ExpandEnvironmentStringsW"] = result_addr

    # 00030645 - 000305E6 = 0x5F
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x5F, callback=handler_ret_ExpandEnvironmentStringsW)

    params = {"src": src}
    return retn_True(params)


def protect_value_to_str(protect):
    """
        parse protect value to string
    """
    protect_str = ""
    if protect & 0x10:
        protect_str = protect_str + "|" + "PAGE_EXECUTE"
    if protect & 0x20:
        protect_str = protect_str + "|" + "PAGE_EXECUTE_READ"
    if protect & 0x40:
        protect_str = protect_str + "|" + "PAGE_EXECUTE_READWRITE"
    if protect & 0x80:
        protect_str = protect_str + "|" + "PAGE_EXECUTE_WRITECOPY"
    if protect & 0x01:
        protect_str = protect_str + "|" + "PAGE_NOACCESS"
    if protect & 0x02:
        protect_str = protect_str + "|" + "PAGE_READONLY"
    if protect & 0x04:
        protect_str = protect_str + "|" + "PAGE_READWRITE"
    if protect & 0x08:
        protect_str = protect_str + "|" + "PAGE_WRITECOPY"
    if protect & 0x40000000:
        protect_str = protect_str + "|" + "PAGE_TARGETS_INVALID"
    if protect & 0x40000000:
        protect_str = protect_str + "|" + "PAGE_TARGETS_NO_UPDATE"

    protect_str = protect_str.strip("|")

    return protect_str


def handler_VirtualProtectEx(dbg):
    """
        parse param

        kernel32.VirtualProtectEx

        VirtualProtect-->VirtualProtectEx-->NtProtectVirtualMemory(ntdll)

          _In_  HANDLE hProcess,
          _In_  LPVOID lpAddress,
          _In_  SIZE_T dwSize,
          _In_  DWORD  flNewProtect,
          _Out_ PDWORD lpflOldProtect
    """
    addr = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0xC)
    protect = read_stack_int32(dbg, 0x10)
    protect_str = protect_value_to_str(protect)

    params = {"addr": "%.8X" % addr, "size_protect": "%.8X" % size, "protect": protect_str}
    return retn_True(params)


def handler_MiniDumpWriteDump(dbg):
    """
        parse params
    """
    pid = read_stack_int32(dbg, 8)
    pid_str = _pid_to_procname(dbg, pid)

    params = {"proc": pid_str}
    return retn_True(params)


def handler_SetErrorMode(dbg):
    """
        parse param

        kernel32.SetErrorMode

        SetErrorMode-->NtSetInformationProcess

            _In_ UINT uMode
    """
    mode = read_stack_int32(dbg, 4)

    mode_str = ""
    if mode & 1:
        mode_str = mode_str + "|" + "SEM_FAILCRITICALERRORS"
    if mode & 2:
        mode_str = mode_str + "|" + "SEM_NOGPFAULTERRORBOX"
    if mode & 4:
        mode_str = mode_str + "|" + "SEM_NOALIGNMENTFAULTEXCEPT"
    if mode & 0x8000:
        mode_str = mode_str + "|" + "SEM_NOOPENFILEERRORBOX"

    if len(mode_str) != 0:
        mode_str = mode_str.strip("|")
    else:
        mode_str = "SEM_DEFAULT"

    params = {"mode": mode_str}
    return retn_True(params)


def handler_ShellExecuteExW(dbg):
    """
        param param

        shell32.ShellExecuteExW

        ShellExecuteA-->ShellExecuteExA-->ShellExecuteExW-->ShellExecuteNormal
        ShellExecuteW-->ShellExecuteExW==>>||
        RealShellExecuteA-->RealShellExecuteExA-->ShellExecuteExA==>>||
        RealShellExecuteW-->RealShellExecuteExW-->ShellExecuteExW==>>||
        WOWShellExecute-->RealShellExecuteExA==>>||
        ShellExec_RunDLLA-->_ShellExec_RunDLL-->ShellExecuteExW
        ShellExec_RunDLLW-->_ShellExec_RunDLL==>>||

        ?+ since this will callinto: kernel32.CreateProcessInternalW, so this might be not necessary?

          LPSHELLEXECUTEINFO lpExecInfo
    """
    pinfo = read_stack_int32(dbg, 4)
    verb = read_p_unicode_string(dbg, pinfo + 0xC)
    file = read_p_unicode_string(dbg, pinfo + 0x10)
    parm = read_p_unicode_string(dbg, pinfo + 0x14)
    dir_ = read_p_unicode_string(dbg, pinfo + 0x18)

    _add_proc_to_proc_summary(file)

    params = {"verb": verb, "file": file, "param": parm, "dir": dir_}
    return retn_True(params)


def handler_SHGetFolderPathW(dbg):
    """
        parse params
    """
    csidl = read_stack_int32(dbg, 8)

    csidl_dict = {
        0x0000: "CSIDL_DESKTOP",
        0x0001: "CSIDL_INTERNET",
        0x0002: "CSIDL_PROGRAMS",
        0x0003: "CSIDL_CONTROLS",
        0x0004: "CSIDL_PRINTERS",
        0x0005: "CSIDL_PERSONAL",
        0x0006: "CSIDL_FAVORITES",
        0x0007: "CSIDL_STARTUP",
        0x0008: "CSIDL_RECENT",
        0x0009: "CSIDL_SENDTO",
        0x000a: "CSIDL_BITBUCKET",
        0x000b: "CSIDL_STARTMENU",
        0x000d: "CSIDL_MYMUSIC",
        0x000e: "CSIDL_MYVIDEO",
        0x0010: "CSIDL_DESKTOPDIRECTORY",
        0x0011: "CSIDL_DRIVES",
        0x0012: "CSIDL_NETWORK",
        0x0013: "CSIDL_NETHOOD",
        0x0014: "CSIDL_FONTS",
        0x0015: "CSIDL_TEMPLATES",
        0x0016: "CSIDL_COMMON_STARTMENU",
        0x0017: "CSIDL_COMMON_PROGRAMS",
        0x0018: "CSIDL_COMMON_STARTUP",
        0x0019: "CSIDL_COMMON_DESKTOPDIRECTORY",
        0x001a: "CSIDL_APPDATA",
        0x001b: "CSIDL_PRINTHOOD",
        0x001c: "CSIDL_LOCAL_APPDATA",
        0x001d: "CSIDL_ALTSTARTUP",
        0x001e: "CSIDL_COMMON_ALTSTARTUP",
        0x001f: "CSIDL_COMMON_FAVORITES",
        0x0020: "CSIDL_INTERNET_CACHE",
        0x0021: "CSIDL_COOKIES",
        0x0022: "CSIDL_HISTORY",
        0x0023: "CSIDL_COMMON_APPDATA",
        0x0024: "CSIDL_WINDOWS",
        0x0025: "CSIDL_SYSTEM",
        0x0026: "CSIDL_PROGRAM_FILES",
        0x0027: "CSIDL_MYPICTURES",
        0x0028: "CSIDL_PROFILE",
        0x0029: "CSIDL_SYSTEMX86",
        0x002a: "CSIDL_PROGRAM_FILESX86",
        0x002b: "CSIDL_PROGRAM_FILES_COMMON",
        0x002c: "CSIDL_PROGRAM_FILES_COMMONX86",
        0x002d: "CSIDL_COMMON_TEMPLATES",
        0x002e: "CSIDL_COMMON_DOCUMENTS",
        0x002f: "CSIDL_COMMON_ADMINTOOLS",
        0x0030: "CSIDL_ADMINTOOLS",
        0x0031: "CSIDL_CONNECTIONS",
        0x0035: "CSIDL_COMMON_MUSIC",
        0x0036: "CSIDL_COMMON_PICTURES",
        0x0037: "CSIDL_COMMON_VIDEO",
        0x0038: "CSIDL_RESOURCES",
        0x0039: "CSIDL_RESOURCES_LOCALIZED",
        0x003a: "CSIDL_COMMON_OEM_LINKS",
        0x003b: "CSIDL_CDBURN_AREA",
        0x003d: "CSIDL_COMPUTERSNEARME",
        0x8000: "CSIDL_FLAG_CREATE",
        0x4000: "CSIDL_FLAG_DONT_VERIFY",
        0x2000: "CSIDL_FLAG_DONT_UNEXPAND",
        0x1000: "CSIDL_FLAG_NO_ALIAS",
        0x0800: "CSIDL_FLAG_PER_USER_INIT",
        0xFF00: "CSIDL_FLAG_MASK"
    }

    # 0x0026: "CSIDL_PROGRAM_FILES",
    # todo: change it.

    if csidl in csidl_dict:
        csidl_str = csidl_dict[csidl]
    else:
        csidl_str = "None"

    params = {"csidl": "%.8X-%s" % (csidl, csidl_str)}
    return retn_True(params)


def handler_ret_GetComputerNameW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetComputerNameW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_GetComputerNameW"])
    _xrk_api_invoke_retn_detail(dbg, "GetComputerNameW", ret_dict={"cmp_name": result_str})

    del callback_runtime["addr_result_GetComputerNameW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetComputerNameW(dbg):
    """
        record result

        kernel32.GetComputerNameW

        GetComputerNameA-->GetComputerNameW-->NtOpenKey/NtCreateKey(ntdll)

          _Out_   LPTSTR  lpBuffer,
          _Inout_ LPDWORD lpnSize
    """
    global callback_runtime
    assert "addr_result_GetComputerNameW" not in callback_runtime

    callback_runtime["addr_result_GetComputerNameW"] = read_stack_int32(dbg, 4)
    # 000317A3 - 000316B7 = 0xEC
    dbg.install_hook_by_tid(dbg.cur_eip() + 0xEC, callback=handler_ret_GetComputerNameW)

    return retn_True(params)


def handler_ret_GetComputerNameExW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetComputerNameExW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_GetComputerNameExW"])
    _xrk_api_invoke_retn_detail(dbg, "GetComputerNameExW", ret_dict={"cmp_name": result_str})

    del callback_runtime["addr_result_GetComputerNameExW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetComputerNameExW(dbg):
    """
        record result

        kernel32.GetComputerNameExW

        GetComputerNameExA-->GetComputerNameExW-->BasepGetNameFromReg

          _In_    COMPUTER_NAME_FORMAT NameType,
          _Out_   LPTSTR               lpBuffer,
          _Inout_ LPDWORD              lpnSize
    """
    type_ = read_stack_int32(dbg, 4)
    type_dict = {
        0: "ComputerNameNetBIOS",
        1: "ComputerNameDnsHostname",
        2: "ComputerNameDnsDomain",
        3: "ComputerNameDnsFullyQualified",
        4: "ComputerNamePhysicalNetBIOS",
        5: "ComputerNamePhysicalDnsHostname",
        6: "ComputerNamePhysicalDnsDomain",
        7: "ComputerNamePhysicalDnsFullyQualified",
        8: "ComputerNameMax"
    }
    if type_ in type_dict:
        type_str = type_dict[type_]
    else:
        type_str = "None"

    params = "(type:%s)" % type_str

    # there are special occasions where "GetComputerNameExW" is invoked again before last "retn" triggered.
    global callback_runtime
    if "addr_result_GetComputerNameExW" not in callback_runtime:

        callback_runtime["addr_result_GetComputerNameExW"] = read_stack_int32(dbg, 8)
        # 0002026B - 000201D9 = 0x92
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x92, callback=handler_ret_GetComputerNameExW)

        return retn_True(params)

    else:
        return retn_True(params, ["invoked again before last retn triggered, so we're ignoring this result string"])

    return params


def handler_ret_GetCurrentDirectoryA(dbg):
    """
        modify result
    """
    global callback_runtime
    assert "addr_result_GetCurrentDirectoryA" in callback_runtime

    result_str = read_ascii_string(dbg, callback_runtime["addr_result_GetCurrentDirectoryA"])

    assert len(api_global_config["fake_module_file_name"]) != 0
    write_ascii_string(dbg, callback_runtime["addr_result_GetCurrentDirectoryA"], api_global_config["fake_module_file_name"])

    _xrk_api_invoke_retn_detail(dbg, "GetCurrentDirectoryA", ret_dict={"cur_dir": result_str}, extrainfo="force ret to: %s" % api_global_config["fake_module_file_name"])

    del callback_runtime["addr_result_GetCurrentDirectoryA"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetCurrentDirectoryA(dbg):
    """
        might modify result
    """
    if len(api_global_config["fake_module_file_name"]) != 0:

        global callback_runtime
        assert "addr_result_GetCurrentDirectoryA" not in callback_runtime

        callback_runtime["addr_result_GetCurrentDirectoryA"] = read_stack_int32(dbg, 8)
        # 000350A3 - 00035016 = 0x8D
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x8D, callback=handler_ret_GetCurrentDirectoryA)

    return retn_True()


def handler_ret_GetCurrentDirectoryW(dbg):
    """
        modify result
    """
    global callback_runtime
    assert "addr_result_GetCurrentDirectoryW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_GetCurrentDirectoryW"])

    assert len(api_global_config["fake_module_file_name"]) != 0
    write_unicode_string(dbg, callback_runtime["addr_result_GetCurrentDirectoryW"], api_global_config["fake_module_file_name"])

    _xrk_api_invoke_retn_detail(dbg, "GetCurrentDirectoryW", ret_dict={"cur_dir": result_str}, extrainfo="force ret to: %s" % api_global_config["fake_module_file_name"])

    del callback_runtime["addr_result_GetCurrentDirectoryW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetCurrentDirectoryW(dbg):
    """
        might modify result
    """
    if len(api_global_config["fake_module_file_name"]) != 0:

        global callback_runtime
        assert "addr_result_GetCurrentDirectoryW" not in callback_runtime

        callback_runtime["addr_result_GetCurrentDirectoryW"] = read_stack_int32(dbg, 8)
        # 0000B91E - 0000B907 = 0x17
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x17, callback=handler_ret_GetCurrentDirectoryW)

    return retn_True()


def handler_ret_GetModuleFileNameW(dbg):
    """
        modify result
    """
    global callback_runtime
    assert "addr_result_GetModuleFileNameW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_GetModuleFileNameW"])

    if len(api_global_config["fake_module_file_name"]) != 0:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameW", ret_dict={"name": result_str}, extrainfo="force ret to: %s" % api_global_config["fake_module_file_name"])
            write_unicode_string(dbg, callback_runtime["addr_result_GetModuleFileNameW"], api_global_config["fake_module_file_name"])

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameW", ret_dict={"name": result_str}, extrainfo="intrude debugee not allowed, so we cancel it")

    del callback_runtime["addr_result_GetModuleFileNameW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())

    return defines.DBG_CONTINUE


def handler_GetModuleFileNameW(dbg):
    """
        might modify result

        kernel32.GetModuleFileNameW

        GetModuleFileNameA-->GetModuleFileNameW

          _In_opt_ HMODULE hModule,
          _Out_    LPTSTR  lpFilename,
          _In_     DWORD   nSize
    """
    h_md = read_stack_int32(dbg, 4)

    if h_md == 0 and len(api_global_config["fake_module_file_name"]) != 0:

        global callback_runtime
        assert "addr_result_GetModuleFileNameW" not in callback_runtime
        callback_runtime["addr_result_GetModuleFileNameW"] = read_stack_int32(dbg, 8)
        # 0000B4FE - 0000B465 = 0x99
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x99, callback=handler_ret_GetModuleFileNameW)

    return retn_True()


def handler_ret_GetModuleFileNameExW(dbg):
    """
        modify result
    """
    global callback_runtime
    assert "addr_result_GetModuleFileNameExW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_GetModuleFileNameExW"])

    if len(api_global_config["fake_module_file_name"]) != 0:

        if api_global_config["is_intrude_debugee"]:

            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameExW", ret_dict={"name": result_str}, extrainfo="force ret to: %s" % api_global_config["fake_module_file_name"])
            write_unicode_string(dbg, callback_runtime["addr_result_GetModuleFileNameExW"], api_global_config["fake_module_file_name"])

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameExW", ret_dict={"name": result_str}, extrainfo="intrude debugee not allowed, so we cancel it")

    del callback_runtime["addr_result_GetModuleFileNameExW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())

    return defines.DBG_CONTINUE


def handler_GetModuleFileNameExW(dbg):
    """
        might modify result
    """
    h_md = read_stack_int32(dbg, 8)

    if h_md == 0 and len(api_global_config["fake_module_file_name"]) != 0:

        global callback_runtime
        assert "addr_result_GetModuleFileNameExW" not in callback_runtime
        callback_runtime["addr_result_GetModuleFileNameExW"] = read_stack_int32(dbg, 0xC)
        # 000017D3 - 0000176A = 0x69
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x69, callback=handler_ret_GetModuleFileNameExW)

    return retn_True()


def handler_GetProcessImageFileNameA(dbg):
    """
        might modify result
    """
    # todo: we only modify result when querying current process
    return retn_True()


def handler_GetProcessImageFileNameW(dbg):
    """
        might modify result
    """
    # todo: we only modify result when querying current process
    return retn_True()


def handler_ret_GetVersion(dbg):
    """
        record result
    """
    _xrk_api_invoke_retn_detail(dbg, "GetVersion", ret_dict={"ver": "%d" % dbg.context.Eax})

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetVersion(dbg):
    """
        record result

        kernel32.GetVersion

          void
    """
    # 0001129A - 0001126A = 0x30
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x30, callback=handler_ret_GetVersion)

    return retn_True()


def handler_ret_GetVersionExW(dbg):
    """
    """
    global callback_runtime
    assert "addr_result_GetVersionExW" in callback_runtime

    major_ver = read_int32(dbg, callback_runtime["addr_result_GetVersionExW"] + 4)
    minor_ver = read_int32(dbg, callback_runtime["addr_result_GetVersionExW"] + 8)
    build_num = read_int32(dbg, callback_runtime["addr_result_GetVersionExW"] + 0xC)
    platform_id = read_int32(dbg, callback_runtime["addr_result_GetVersionExW"] + 0x10)
    csd_ver = read_p_ascii_string(dbg, callback_runtime["addr_result_GetVersionExW"] + 0x14)

    _xrk_api_invoke_retn_detail(dbg, "GetVersionExW", ret_dict={"ver": "%d:%d-%d-%d-%s" % (major_ver, minor_ver, build_num, platform_id, csd_ver)})

    del callback_runtime["addr_result_GetVersionExW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetVersionExW(dbg):
    """
        record result

        kernel32.GetVersionExW

        GetVersionExA-->GetVersionExW

          _Inout_ LPOSVERSIONINFO lpVersionInfo
    """
    global callback_runtime
    assert "addr_result_GetVersionExW" not in callback_runtime

    callback_runtime["addr_result_GetVersionExW"] = read_stack_int32(dbg, 4)
    # 0000AF32 - 0000AEF5 = 0x3D
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x3D, callback=handler_ret_GetVersionExW)

    return retn_True()


def handler_ret_GetPrivateProfileStringA(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetPrivateProfileStringA" in callback_runtime

    result_str = read_ascii_string(dbg, callback_runtime["addr_result_GetPrivateProfileStringA"])
    _xrk_api_invoke_retn_detail(dbg, "GetPrivateProfileStringA", ret_dict={"ret_str": result_str})

    del callback_runtime["addr_result_GetPrivateProfileStringA"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetPrivateProfileStringA(dbg):
    """
        record result

        kernel32.GetPrivateProfileStringA

        GetPrivateProfileIntA-->GetPrivateProfileStringA-->BaseDllReadWriteIniFile
        GetPrivateProfileSectionNamesA-->GetPrivateProfileStringA==>>||
        GetPrivateProfileStructA-->GetPrivateProfileStringA==>>||
        GetProfileStringA-->GetPrivateProfileStringA==>>||
        GetProfileIntA-->GetPrivateProfileIntA==>>||

          _In_  LPCTSTR lpAppName,
          _In_  LPCTSTR lpKeyName,
          _In_  LPCTSTR lpDefault,
          _Out_ LPTSTR  lpReturnedString,
          _In_  DWORD   nSize,
          _In_  LPCTSTR lpFileName
    """
    app_name = read_stack_p_ascii_string(dbg, 4)
    key_name = read_stack_p_ascii_string(dbg, 8)
    default = read_stack_p_ascii_string(dbg, 0xC)
    file = read_stack_p_ascii_string(dbg, 0x18)

    global callback_runtime
    assert "addr_result_GetPrivateProfileStringA" not in callback_runtime
    callback_runtime["addr_result_GetPrivateProfileStringA"] = read_stack_int32(dbg, 0x10)
    # 00032BC0 - 00032B6E = 0x52
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x52, callback=handler_ret_GetPrivateProfileStringA)

    params = {"app": app_name, "key": key_name, "default": default, "file": file}
    return retn_True(params)


def handler_ret_GetPrivateProfileStringW(dbg):
    """
        record result
    """
    global callback_runtime
    assert "addr_result_GetPrivateProfileStringW" in callback_runtime

    result_str = read_unicode_string(dbg, callback_runtime["addr_result_GetPrivateProfileStringW"])
    _xrk_api_invoke_retn_detail(dbg, "GetPrivateProfileStringW", ret_dict={"ret_str": result_str})

    del callback_runtime["addr_result_GetPrivateProfileStringW"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetPrivateProfileStringW(dbg):
    """
        record result

        kernel32.GetPrivateProfileStringW

        GetPrivateProfileIntW-->GetPrivateProfileStringW-->BaseDllReadWriteIniFile
        GetPrivateProfileSectionNamesW-->GetPrivateProfileStringW==>>||
        GetPrivateProfileStructW-->GetPrivateProfileStringW==>>||
        GetProfileStringW-->GetPrivateProfileStringW==>>||
        GetProfileIntW-->GetPrivateProfileIntW==>>||

          _In_  LPCTSTR lpAppName,
          _In_  LPCTSTR lpKeyName,
          _In_  LPCTSTR lpDefault,
          _Out_ LPTSTR  lpReturnedString,
          _In_  DWORD   nSize,
          _In_  LPCTSTR lpFileName
    """
    app_name = read_stack_p_unicode_string(dbg, 4)
    key_name = read_stack_p_unicode_string(dbg, 8)
    default = read_stack_p_unicode_string(dbg, 0xC)
    file = read_stack_p_unicode_string(dbg, 0x18)

    global callback_runtime
    assert "addr_result_GetPrivateProfileStringW" not in callback_runtime
    callback_runtime["addr_result_GetPrivateProfileStringW"] = read_stack_int32(dbg, 0x10)
    # 0000FA61 - 0000F9ED = 0x74
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x74, callback=handler_ret_GetPrivateProfileStringW)

    params = {"app": app_name, "key": key_name, "default": default, "file": file}
    return retn_True(params)


def handler_SetTimer(dbg):
    """
        nothing special....

        user32.SetTimer

          _In_opt_ HWND      hWnd,
          _In_     UINT_PTR  nIDEvent,
          _In_     UINT      uElapse,
          _In_opt_ TIMERPROC lpTimerFunc
    """
    evt_id = read_stack_int32(dbg, 8)
    elaspe = read_stack_int32(dbg, 0xC)
    cbk = read_stack_int32(dbg, 0x10)

    params = {"evt_id": evt_id, "elaspe": elaspe, "cbk": "%.8X" % cbk}
    return retn_True(params)


def handler_KillTimer(dbg):
    """
        nothing special....

        user32.KillTimer

          _In_opt_  HWND hWnd,
          _In_      UINT_PTR uIDEvent
    """
    evt_id = read_stack_int32(dbg, 8)

    params = {"evt_id": "%d" % evt_id}
    return retn_True(params)


def handler_retn_VirtualAllocEx(dbg):
    """
        record alloc result
    """
    addr = dbg.context.Eax

    _xrk_api_invoke_retn_detail(dbg, "VirtualAllocEx", ret_dict={"ret_addr": "%.8X" % addr})

    if api_global_config["is_bpmmwrite_alloc_retn"]:
        # todo
        # we only set first 2 bytes, check if is PE header
        pass

    if api_global_config["is_record_alloc_retn"]:
        pass

    # this is one shot
    dbg.uninstall_hook_by_tid(dbg.cur_eip())

    return defines.DBG_CONTINUE


def handler_VirtualAllocEx(dbg):
    """
        might record alloc result

        kernel32.VirtualAllocEx

        VirtualAlloc(kernel32)-->VirtualAllocEx(kernel32)-->NtAllocateVirtualMemory(ntdll)

          _In_     HANDLE hProcess,
          _In_opt_ LPVOID lpAddress,
          _In_     SIZE_T dwSize,
          _In_     DWORD  flAllocationType,
          _In_     DWORD  flProtect
    """
    addr = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0xC)
    h_proc = read_stack_int32(dbg, 4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)
    protect = read_stack_int32(dbg, 0x14)
    protect_str = protect_value_to_str(protect)

    if api_global_config["is_bpmmwrite_alloc_retn"] or api_global_config["is_record_alloc_retn"]:
        # 00009B49 - 00009B02 = 0x47
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x47, callback=handler_retn_VirtualAllocEx)

    params = {"proc": h_proc_str, "size_alloc": "%.8X" % size, "protect": protect_str}
    if addr != 0:
        params["addr"] = "%.8X" % addr

    return retn_True(params)


def handler_retn_RtlAllocateHeap(dbg):
    """
        record alloc result
    """
    addr = dbg.context.Eax

    _xrk_api_invoke_retn_detail(dbg, "RtlAllocateHeap", ret_dict={"ret_addr": "%.8X" % addr})

    if api_global_config["is_bpmmwrite_alloc_retn"]:
        # todo
        # we only set first 2 bytes, check if is PE header
        pass

    if api_global_config["is_record_alloc_retn"]:
        pass

    # this is one shot
    dbg.uninstall_hook_by_tid(dbg.cur_eip())

    return defines.DBG_CONTINUE


def handler_RtlAllocateHeap(dbg):
    """
        might record alloc result

        ntdll.RtlAllocateHeap

        kernel32.LocalAlloc -->ntdll.RtlAllocateHeap
        kernel32.HeapAlloc-->ntdll.RtlAllocateHeap
        kernel32.GlobalAlloc-->ntdll.RtlAllocateHeap
        kernel32.GlobalReAlloc-->ntdll.RtlAllocateHeap

          _In_     PVOID  HeapHandle,
          _In_opt_ ULONG  Flags,
          _In_     SIZE_T Size

        flags:
        HEAP_GENERATE_EXCEPTIONS 0x00000004
        HEAP_NO_SERIALIZE        0x00000001
        HEAP_ZERO_MEMORY         0x00000008
    """
    flags = read_stack_int32(dbg, 8)
    size = read_stack_int32(dbg, 0xC)

    if api_global_config["is_bpmmwrite_alloc_retn"] or api_global_config["is_record_alloc_retn"]:
        # 000101BB - 000100A4 = 0x117
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x117, callback=handler_retn_RtlAllocateHeap)

    flags_str = ""
    if flags & 0x1:
        flags_str = flags_str + "|HEAP_NO_SERIALIZE"
    if flags & 0x4:
        flags_str = flags_str + "|HEAP_GENERATE_EXCEPTIONS"
    if flags & 0x8:
        flags_str = flags_str + "|HEAP_ZERO_MEMORY"

    if len(flags_str) == 0:
        flags_str == "[Unknown]"
    else:
        flags_str = flags_str.strip("|")

    params = {"size_alloc": "%.8X" % size, "flags": flags_str}
    return retn_True(params)


def handler_retn_RtlReAllocateHeap(dbg):
    """
        record alloc result
    """
    addr = dbg.context.Eax

    _xrk_api_invoke_retn_detail(dbg, "RtlReAllocateHeap", ret_dict={"ret_addr": "%.8X" % addr})

    if api_global_config["is_bpmmwrite_alloc_retn"]:
        # todo
        # we only set first 2 bytes, check if is PE header
        pass

    if api_global_config["is_record_alloc_retn"]:
        pass

    # this is one shot
    dbg.uninstall_hook_by_tid(dbg.cur_eip())

    return defines.DBG_CONTINUE


def handler_RtlReAllocateHeap(dbg):
    """
        might record alloc result

        ntdll.RtlReAllocateHeap

        kernel32.HeapReAlloc-->RtlReAllocateHeap(ntdll)

         HANDLE heap,
         ULONG  flags,
         PVOID  ptr,
         SIZE_T size
    """
    flags = read_stack_int32(dbg, 8)
    ptr = read_stack_int32(dbg, 0xC)
    size = read_stack_int32(dbg, 0x10)

    if api_global_config["is_bpmmwrite_alloc_retn"] or api_global_config["is_record_alloc_retn"]:
        # 00019D8A - 00019B80 = 0x20A
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x20A, callback=handler_retn_RtlReAllocateHeap)

    # flags might be wrong. i don't know it's corrent values... lol...
    flags_str = ""
    if flags & 0x1:
        flags_str = flags_str + "|HEAP_NO_SERIALIZE"
    if flags & 0x4:
        flags_str = flags_str + "|HEAP_GENERATE_EXCEPTIONS"
    if flags & 0x8:
        flags_str = flags_str + "|HEAP_ZERO_MEMORY"

    if len(flags_str) == 0:
        flags_str == "[Unknown]"
    else:
        flags_str = flags_str.strip("|")

    params = {"size_alloc": "%.8X" % size, "flags": flags_str, "ptr": "%.8X" % ptr}
    return retn_True(params)


def handler_GetProcAddress(dbg):
    """
        param might be string or int

        kernel32.GetProcAddress

        GetProcAddress-->LdrGetProcedureAddress

          HMODULE hModule,
          LPCWSTR lpProcName
    """
    check = read_stack_int32(dbg, 8)

    params = None
    extrainfo = None

    if check > 0x1000:
        # must be ascii string
        proc = read_stack_p_ascii_string(dbg, 8, max_bytes=256)
        if proc:

            assert len(proc) != 0
            params = {"proc": proc}

            # TODO: 将这里的东西添加为输出内容

        else:
            extrainfo = "(get param fail, stack var: %.8X)" % check

    if params is None:
        params = {"ordinal": "%d" % check}

    return retn_True(params, extrainfo)


def handler_ret_GetCommandLineA(dbg):
    """
        record result
    """
    result_str = read_ascii_string(dbg, dbg.context.Eax)

    if len(api_global_config["fake_module_file_name"]) != 0:
        if result_str.count("\"") == 2:

            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineA", ret_dict={"cmd_line": result_str}, extrainfo="force retn to: %s" % api_global_config["fake_module_file_name"])
            write_ascii_string(dbg, dbg.context.Eax, "\"" + api_global_config["fake_module_file_name"] + "\"")

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineA", ret_dict={"cmd_line": result_str})
            _pt_log(">>> not implemented")
            assert False

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetCommandLineA(dbg):
    """
        record result

        kernel32.GetCommandLineA

          void
    """
    # 00012FB2 - 00012FAD = 0x5
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x05, callback=handler_ret_GetCommandLineA)

    return retn_True()


def handler_ret_GetCommandLineW(dbg):
    """
        record result
    """
    result_str = read_unicode_string(dbg, dbg.context.Eax)

    if len(api_global_config["fake_module_file_name"]) != 0:
        if result_str.count("\"") == 2:

            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineW", ret_dict={"cmd_line": result_str}, extrainfo="force retn to: %s" % api_global_config["fake_module_file_name"])
            write_unicode_string(dbg, dbg.context.Eax, "\"" + api_global_config["fake_module_file_name"] + "\"")

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineW", ret_dict={"cmd_line": result_str})
            _pt_log(">>> not implemented")
            assert False

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetCommandLineW(dbg):
    """
        record result

        kernel32.GetCommandLineW

          void
    """
    # 00017018 - 00017013 = 0x5
    dbg.install_hook_by_tid(dbg.cur_eip() + 0x05, callback=handler_ret_GetCommandLineW)

    return retn_True()


def handler_ret_GetTickCount(dbg):
    """
        modify result
    """
    cur_ret = dbg.context.Eax

    global callback_runtime
    if callback_runtime["fake_tick_gap"] == 0:

        # first time we modify result of GetTickCount, and we calc gap here

        assert api_global_config["fake_tick_start"] != 0

        new_ret = api_global_config["fake_tick_start"]
        callback_runtime["fake_tick_gap"] = api_global_config["fake_tick_start"] - cur_ret

    else:
        # we do this, because we specified "fake_tick_start" or SleepEx is called.
        new_ret = cur_ret + callback_runtime["fake_tick_gap"]

    if api_global_config["is_intrude_debugee"]:

        _xrk_api_invoke_retn_detail(dbg, "GetTickCount", extrainfo="force ret from %d to %d, gap: %d" % (cur_ret, new_ret, callback_runtime["fake_tick_gap"]))
        dbg.set_register("EAX", new_ret)

    else:
        _xrk_api_invoke_retn_detail(dbg, "GetTickCount", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetTickCount(dbg):
    """
        might mofify result

        kerner32.GetTickCount

          void
    """
    global callback_runtime
    if "fake_tick_gap" not in callback_runtime:
        callback_runtime["fake_tick_gap"] = 0

    if api_global_config["fake_tick_start"] != 0 or callback_runtime["fake_tick_gap"] != 0:

        # 0000933C - 0000932E = 0xE
        dbg.install_hook_by_tid(dbg.cur_eip() + 0xE, callback=handler_ret_GetTickCount)

    return retn_True()


def handler_ret_GetSystemTime(dbg):
    """
        modify result
    """
    global callback_runtime
    assert "addr_result_GetSystemTime" in callback_runtime

    cur_sys_time = parse_systime(dbg, callback_runtime["addr_result_GetSystemTime"])

    if callback_runtime["fake_systime_gap"] == 0:

        # the first time call GetSystemTime() and we specified "fake_systime_start"
        assert api_global_config["fake_systime_start"] != 0

        new_time = api_global_config["fake_systime_start"]
        callback_runtime["fake_systime_gap"] = calc_systime_gap(api_global_config["fake_systime_start"], cur_sys_time)

    else:
        # we specified "fake_system_start" or SleepEx has already been invoked
        new_time = add_systime_gap(cur_sys_time, callback_runtime["fake_systime_gap"])

    _xrk_api_invoke_retn_detail(dbg, "GetSystemTime", ret_dict={"sys_time": systime_str(cur_sys_time)}, extrainfo="modify to: %s" % systime_str(new_time))

    dbg_write_systime(dbg, callback_runtime["addr_result_GetSystemTime"], new_time)

    del callback_runtime["addr_result_GetSystemTime"]
    dbg.uninstall_hook_by_tid(dbg.cur_eip())
    return defines.DBG_CONTINUE


def handler_GetSystemTime(dbg):
    """
        might modify result

        kernel32.GetSystemTime

        GetSystemTime-->??/RtlTimeToTimeFields

          LPSYSTEMTIME lpSystemTime
    """
    global callback_runtime
    if "fake_systime_gap" not in callback_runtime:
        callback_runtime["fake_systime_gap"] = 0

    if api_global_config["fake_systime_start"] != 0 or callback_runtime["fake_systime_gap"] != 0:

        assert "addr_result_GetSystemTime" not in callback_runtime
        callback_runtime["addr_result_GetSystemTime"] = read_stack_int32(dbg, 4)
        # 000017E1 - 0000176F = 0x72
        dbg.install_hook_by_tid(dbg.cur_eip() + 0x72, callback=handler_ret_GetSystemTime)

    return retn_True()


def handler_GetModuleHandleW(dbg):
    """
        parse params

        kernel32.GetModuleHandleW

        GetModuleHandleA-->GetModuleHandleW-->BasepGetModuleHandleExW

          _In_opt_ LPCTSTR lpModuleName
    """
    file_v = read_stack_int32(dbg, 4)
    if file_v == 0:

        file_str = "[Debugee]"

        params = {"file": file_str}
        return retn_True(params, ["retrieving mm pointer to debugee"])

    else:
        file_str = read_stack_p_ascii_string(dbg, 4)

        params = {"file": file_str}
        return retn_True(params)

    return params


def handler_GetModuleHandleExW(dbg):
    """
        parse params

        kernel32.GetModuleHandleExW

        GetModuleHandleExA-->GetModuleHandleExW-->BasepGetModuleHandleExW

          _In_     DWORD   dwFlags,
          _In_opt_ LPCTSTR lpModuleName,
          _Out_    HMODULE *phModule
    """
    file_v = read_stack_int32(dbg, 8)
    if file_v == 0:

        file_str = "[Debugee]"

        params = {"file": file_str}
        return retn_True(params, ["retrieving mm pointer to debugee"])

    else:
        file_str = read_stack_p_ascii_string(dbg, 8)

        params = {"file": file_str}
        return retn_True(params)

    return params


def handler_WaitForSingleObjectEx(dbg):
    """
        ignore wait, step forward and change ret result

        kernel32.WaitForSingleObjectEx

        WaitForSingleObject-->WaitForSingleObjectEx-->NtWaitForSingleObject

          HANDLE hHandle,
          DWORD dwMilliseconds
          BOOL bAlertable
    """
    if api_global_config["is_ignore_all_wait_obj"]:

        if api_global_config["is_intrude_debugee"]:

            # 000095A4 - 000095BC = -0x18
            dbg.set_register("EIP", dbg.cur_eip() - 0x18)
            dbg.set_register("EAX", 0)

            return retn_True(meta_list=["brute force to retn!"])

        else:
            return retn_True(meta_list=["intrude debugee not allowed, so we cancel it"])

    else:
        return retn_True()


def handler_WaitForMultipleObjectsEx(dbg):
    """
        ignore wait, step forward and change ret result

        kernel32.WaitForMultipleObjectsEx

        WaitForMultipleObjects-->WaitForMultipleObjectsEx-->NtWaitForMultipleObjects

          _In_       DWORD  nCount,
          _In_ const HANDLE *lpHandles,
          _In_       BOOL   bWaitAll,
          _In_       DWORD  dwMilliseconds
          _In_       BOOL bAlertable
    """
    cnt = read_stack_int32(dbg, 4)
    params = {"cnt": "%d" % cnt}

    if api_global_config["is_ignore_all_wait_obj"]:

        if api_global_config["is_intrude_debugee"]:

            # 0x00002600 - 00002550 = 0xB0
            dbg.set_register("EIP", dbg.cur_eip() + 0xB0)
            dbg.set_register("EAX", 0)

            return retn_True(params, meta_list=["brute force to retn!"])

        else:
            return retn_True(params, meta_list=["intrude debugee not allowed, so we cancel it"])

    else:
        return retn_True(params)

    return params


def handler_ZwDelayExecution(dbg):
    """
        shorten sleep
    """
    alertable = read_stack_int32(dbg, 4)
    msecs = read_stack_int32(dbg, 8)

    params = {"alertable": "%d" % alertable, "msecs": "%d" % msecs}
    return retn_True(params)


def handler_SleepEx(dbg):
    """
        shorten sleep

        kernel32.SleepEx

        Sleep-->SleepEx-->NtDelayExecution(ntdll)

          _In_  DWORD dwMilliseconds,
          _In_  BOOL bAlertable
    """
    msecs = dbg.read_stack_int32(4)
    alertable = dbg.read_stack_int32(8)

    params = {"alertable": "%d" % alertable, "msecs": "%d" % msecs}

    if msecs >= 20:

        if api_global_config["is_intrude_debugee"]:

            dbg.write_stack_int32(4, 1)

            # update tick gap
            global callback_runtime
            if callback_runtime["fake_tick_gap"] is None:
                callback_runtime["fake_tick_gap"] = msecs
            else:
                callback_runtime["fake_tick_gap"] = callback_runtime["fake_tick_gap"] + msecs

            # update systime gap
            if "fake_systime_gap" not in callback_runtime:
                callback_runtime["fake_systime_gap"] = msecs
            else:
                callback_runtime["fake_systime_gap"] = callback_runtime["fake_systime_gap"] + msecs

            return retn_True(params, ["brute force new sleep msecs: %d -> %d" % (msecs, 1)])

        else:
            return retn_True(params, ["intrude debugee not allowed, so we cancel it..."])
    else:

        return retn_True(params)


def handler_TerminateProcess(dbg):
    """
        parse params, and update global var

        kernel32.TerminateProcess

        TerminateProcess-->NtTerminateProcess(ntdll)

          _In_ HANDLE hProcess,
          _In_ UINT   uExitCode
    """
    code = dbg.read_stack_int32(8)
    h_proc = dbg.read_stack_int32(4)
    if h_proc == 0xFFFFFFFF:
        h_proc_str = "[Debugee]"

        # TODO: is_normal_termination = True

    else:
        h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    params = {"proc": h_proc_str, "code": "%d" % code}
    return retn_True(params)


def handler_ExitProcess(dbg):
    """
        update global var

        kernel32.ExitProcess

        ExitProcess-->LdrShutdownProcess

          _In_ UINT uExitCode
    """
    code = dbg.read_stack_int32(4)

    # TODO: is_normal_termination = True

    params = {"code": "%d" % code}
    return retn_True(params)


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
