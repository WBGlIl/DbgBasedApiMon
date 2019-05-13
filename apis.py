# -*- coding: utf-8 -*-

"""
apis list and handlers
"""

import os
import ctypes
import struct
import socket
import datetime

import log
import sym
import util
import msdn
# import psutil # not available on xp sp3
import output
import defines

# ---------------------------------------------------------------------------

# is shorten sleep
# global v_tmp_is_shorten_sleep
v_tmp_is_shorten_sleep = False

# ignore mutex names
# global v_tmp_ignore_mutex_names
v_tmp_ignore_mutex_names = None

# ignore all mutex
v_tmp_is_ignore_all_mutex = False

# is ignore all wait for single/multiple objects
# global v_tmp_is_ignore_all_wait_obj
v_tmp_is_ignore_all_wait_obj = False

# is modify ret of GetTickCount()
# global v_tmp_fake_tick_start
v_tmp_fake_tick_start = None

# is modify ret of GetSystemTime()
# defines.SYSTEMTIME()
v_tmp_fake_systime_start = None

# is record memory alloc result
# global v_tmp_is_record_alloc_retn
v_tmp_is_record_alloc_retn = False

# is set mm write bp at alloc result
v_tmp_is_bpmmwrite_alloc_retn = False

# api type str
v_tmp_gather_api_type_str = None

# is backup remove dir
v_tmp_is_backup_remove_dir_file = False

# fake module file name
# influnced apis: GetCurrentDirectoryA/GetCurrentDirectoryW/GetModuleFileNameW/GetModuleFileNameExW/GetCommandLineA/GetCommandLineW
v_tmp_fake_module_file_name = None

# is all socket api resutl success
v_tmp_is_all_socket_success = False

# new sock connect ip
v_tmp_new_sock_connect_ip = None

# new sock connect port
v_tmp_new_sock_connect_port = None

# new http connect addr
v_tmp_new_http_connect_addr = None

# is save send data
v_tmp_is_save_send_data_to_file = False

# is save recv data to file
v_tmp_is_save_recv_data_to_file = False

# is access return success
v_tmp_is_access_success = False

# ignore api names
v_tmp_ignore_api_names = []

# ignore cat names
v_tmp_ignore_cat_names = []

# is intrude debugee
v_tmp_is_intrude_debugee = False

# equal cmp strings
v_tmp_equal_cmp_strings = None

# is check call stack
v_tmp_is_check_call_stack = True


# ---------------------------------------------------------------------------

# is pt all api invoke only
# global v_tmp_is_pt_all_api_invoke_only
v_tmp_is_pt_all_api_invoke_only = False

# is always pt api invoke
# global v_tmp_is_pt_all_api_invoke_always
v_tmp_is_pt_all_api_invoke_always = False

# is always pt api call stacks
# global v_tmp_is_pt_all_api_stacks_always
v_tmp_is_pt_all_api_stacks_always = False

# is pt filtered api call stacks
v_tmp_is_pt_filtered_api_stacks = False

# is print param log detail when ParamLogCtrl.get_log()
# global v_tmp_is_pt_param_log_detail
v_tmp_is_pt_param_log_detail = False

# is pt bp detail when set bp at api
# global v_tmp_is_pt_when_set_api_bp
v_tmp_is_pt_when_set_api_bp = False

# is pt when new dll load
# global v_tmp_is_pt_new_dll_load
v_tmp_is_pt_new_dll_load = False

# is log api invoke time
# global v_tmp_is_pt_api_invoke_time
v_tmp_is_pt_api_invoke_time = False

# is pt call stacks when process exit
v_tmp_is_pt_process_exit_call_stacks = False

# is pt api summary when process exit
v_tmp_is_pt_process_exit_api_summary = False

# is pt debugee manual resovled funcs
v_tmp_is_pt_manual_resolved_funcs = False

# ---------------------------------------------------------------------------

#
# this is a global dynamic dict
# {
#     "kernel32.dll": [api_ctrl(), api_ctrl(), ...],
#     "advapi32.dll": [api_ctrl(), api_ctrl(), ...],
#     ...
# }
#
# generate global api_ctrl dict
# global v_tmp_dll_apis
v_tmp_dll_apis = None

# global addr to api_ctrl dict
# modified only when install api hook
# global v_tmp_addr_to_api
v_tmp_addr_to_api = {}

# gap to add to the result of GetTickCount()
# init when first call GetTickCount(),  updated when call SleepEx()
v_tmp_fake_tick_gap = None

# gat to add to the result of GetSystemTime()
# init when first call GetSystemTime(), updated when call SleepEx()
v_tmp_fake_systime_gap = None

# last apis invoked
# dict: {tid: api, tid: api}
v_tmp_last_api_name = {}

# is normal termination
v_tmp_is_normal_termination = False

# api invoke summary
# dict: {api: (ok_cnt, no_cnt, all_cnt), api: (ok_cnt, no_cnt, all_cnt)}
# ok_cnt + no_cnt != all_cnt, when only pt api invoke...
v_tmp_api_invoke_summary = {}

# bp hit count
v_tmp_bp_hit_count = 0

# file name summary, for filling report
v_tmp_file_name_summary = []

# reg name summary, for filling report
v_tmp_reg_name_summary = []

# proc name summary, for filling report
v_tmp_proc_name_summary = []

# manual resolved func
v_tmp_manual_resolved_funcs = []

# ---------------------------------------------------------------------------
# api retn address

# retn addrs of api WinHttpCreateUrl
v_tmp_addr_WinHttpCreateUrl_rets = None

# retn addrs of api access
v_tmp_addr_access_rets = None

# api invoke cnt dict runtime
v_tmp_api_invoke_cnt_dict_runtime = {}

# ---------------------------------------------------------------------------
# api result address

# when wnsprintfA ret, addr that hold result
v_tmp_addr_result_formatA = None

# when wnsprintfW ret, addr that hold result
v_tmp_addr_result_formatW = None

# ret addr of GetModuleFileNameW
v_tmp_addr_result_GetModuleFileNameW = None

# ret addr of GetModuleFileNameExW
v_tmp_addr_result_GetModuleFileNameExW = None

# result address of WinHttpCreateUrl
v_tmp_addr_result_WinHttpCreateUrl = None

# result address of GetTempFileNameW
v_tmp_addr_result_GetTempFileNameW = None

# result address of ExpandEnvironmentStringsA
v_tmp_addr_result_ExpandEnvironmentStringsA = None

# result address of ExpandEnvironmentStringsW
v_tmp_addr_result_ExpandEnvironmentStringsW = None

# result address of GetFullPathNameW
v_tmp_addr_result_GetFullPathNameW = None

# result address of recv
v_tmp_addr_result_recv = None

# result address of GetVersionExW
v_tmp_addr_result_GetVersionExW = None

# result address of GetComputerNameW
v_tmp_addr_result_GetComputerNameW = None

# result address of gethostname
v_tmp_addr_result_gethostname = None

# result address of GetTempPathW
v_tmp_addr_result_GetTempPathW = None

# result address of GetSystemDirectoryA
v_tmp_addr_result_GetSystemDirectoryA = None

# result address of GetSystemDirectoryW
v_tmp_addr_result_GetSystemDirectoryW = None

# result address of GetPrivateProfileStringA
v_tmp_addr_result_GetPrivateProfileStringA = None

# result address of GetPrivateProfileStringW
v_tmp_addr_result_GetPrivateProfileStringW = None

# result address of GetSystemTime
v_tmp_addr_result_GetSystemTime = None

# result address of CreateProcessInternalW
v_tmp_addr_result_CreateProcessInternalW = None

# result address of GetComputerNameExW
v_tmp_addr_result_GetComputerNameExW = None


# ---------------------------------------------------------------------------

def _pt_log(line):
    """
        proxy to log.pt_log()
    """
    log.pt_log(line)


# ---------------------------------------------------------------------------
# api_ctrl

# ---------------------------------------------------------------------------
# test

def test_stack_unwind(dbg):
    to_addrs = dbg.stack_unwind()
    if len(to_addrs) == 0:
        _pt_log("empty stack unwind result")
    else:
        _pt_log("stack unwind len: %d" % len(to_addrs))
        for to_addr in to_addrs:
            _pt_log("    %.8X" % to_addr)
        _pt_log("")


def handler_Test(dbg):
    """
        test
    """
    test_stack_unwind(dbg)
    return "handler Test - finish"


# ---------------------------------------------------------------------------
# call stack thing

def resolve_call_stacks(stacks):
    """
        resolve call stacks using symbols

        @param: stacks: list : a list of _share_this.StackFrame() object

        @return: list : a list of _share_this.StackFrame() object
    """
    for stack in stacks:

        if stack.from_md_name is not None:
            from_func_name, from_func_offset = sym.sym_resolve(stack.from_md_name, stack.from_md_offset)
            if from_func_name is not None:
                stack.from_func_name = from_func_name
                stack.from_func_offset = from_func_offset

        if stack.to_md_name is not None:
            to_func_name, to_func_offset = sym.sym_resolve(stack.to_md_name, stack.to_md_offset)
            if to_func_name is not None:
                stack.to_func_name = to_func_name
                stack.to_func_offset = to_func_offset

    return stacks


def get_resolved_call_stacks_default(dbg, depth=None, is_fix_api_start=False):
    """
        get call stack, resolve, return resolved

        @param: depth            :
        @param: is_fix_api_start :

        @return: list : a list of _share_this.StackFrame() object
                 None
    """
    stacks = dbg.get_call_stacks_default(depth=depth, is_fix_api_start=is_fix_api_start)
    return resolve_call_stacks(stacks)


def get_resolved_call_stacks_all(dbg, depth=None, is_fix_api_start=False):
    """
        @param: depth            :
        @param: is_fix_api_start :

        @return: dict : like this: {tid1: resolved_call_stack_list1,
                                    tid2: resolved_call_stack_list2,
                                    ...}
    """
    tid_to_stacks_dict = dbg.get_call_stacks_all(depth=depth, is_fix_api_start=is_fix_api_start)
    ret = {}
    for (tid, stacks) in tid_to_stacks_dict.items():
        ret[tid] = resolve_call_stacks(stacks)
    return ret


def pt_resolved_call_stacks_default(dbg, depth=None, is_fix_api_start=False):
    """
        print call stack of current thread
    """
    stacks = get_resolved_call_stacks_default(dbg, depth=depth, is_fix_api_start=is_fix_api_start)
    if len(stacks) == 0:
        _pt_log("empty call stack")
    else:
        _pt_log("call stack depth: %d" % len(stacks))
        _pt_log("")
        for stack in stacks:
            _pt_log("    %s" % (stack))
        _pt_log("")


def pt_resolved_call_stacks_all(dbg, depth=None, is_fix_api_start=False):
    """
        print call stack of all threads
    """
    tid_to_stacks_dict = get_resolved_call_stacks_all(dbg, depth=depth, is_fix_api_start=is_fix_api_start)
    assert len(tid_to_stacks_dict) >= 1

    _pt_log("tid count: %d" % len(tid_to_stacks_dict))
    _pt_log("")

    for (tid, stacks) in tid_to_stacks_dict.items():

        _pt_log("call stacks of tid %d(depth: %d):" % (tid, len(stacks)))
        for stack in stacks:
            _pt_log("    %s" % stack)
        _pt_log("")
    _pt_log("")


# ---------------------------------------------------------------------------


def _add_file_to_file_summary(file):
    """
        add file path to file summary
    """
    file = file.lower()

    global v_tmp_file_name_summary
    if file is not None and \
            file != util.debugee_name() and \
            file != util.debugee_dir() and \
            file != util.debugee_path() and \
            file not in sym.get_sym_sys_dll_names() and \
            file not in v_tmp_file_name_summary:

        v_tmp_file_name_summary.append(file)


def _add_reg_to_reg_summary(reg):
    """
        add reg path to reg summary
    """
    global v_tmp_reg_name_summary
    if reg is not None and reg not in v_tmp_reg_name_summary:
        v_tmp_reg_name_summary.append(reg)


def _add_proc_to_proc_summary(proc):
    """
        add proc path to proc summary
    """
    global v_tmp_proc_name_summary
    if proc is not None and proc not in v_tmp_proc_name_summary:
        v_tmp_proc_name_summary.append(proc)


def _xrk_api_invoke_detail(dbg, api_name, param_dict=None, extrainfo=None):
    """
        print api call and params

        @param: api_name   : string : api name
        @param: param_dict : dict   : (optional, dft=None)param dict, each item: (param_str: value_str)
        @param: extrainfo  : string : (optional, dft=None)extra info
    """
    # temp check
    if param_dict is not None:
        assert type(param_dict) is dict

    if param_dict is None:

        if extrainfo is None:
            # only pt api name
            _pt_log(">>> api_invoke: (%.8X)%-40s:" % (dbg.dbg.dwThreadId, api_name))

        else:
            # pt api name with  extra info
            _pt_log(">>> api_invoke: (%.8X)%-40s: %s" % (dbg.dbg.dwThreadId, api_name, extrainfo))

    else:
        assert len(param_dict) != 0

        # ---------------------------------------------------------------------------
        # pt params
        has_pt_first_param = False
        for (param_str, value_str) in param_dict.items():

            # ---------------------------------------------------------------------------
            # pt

            if not has_pt_first_param:

                # first line, with first param
                _pt_log(">>> api_invoke: (%.8X)%-40s: %-15s: %s" % (dbg.dbg.dwThreadId, api_name, param_str, value_str))
                has_pt_first_param = True

            else:
                # extra params
                _pt_log(">>>           : %-50s: %-15s: %s" % (" ", param_str, value_str))

            # ---------------------------------------------------------------------------
            # check file/reg/proc

            if (param_str.startswith("file") or param_str.startswith("dir") or param_str.startswith("path")) and \
                    (value_str is not None and len(value_str) != 0 and value_str != "None" and not value_str.startswith("[")):
                _add_file_to_file_summary(value_str)

            if (param_str.startswith("key") or param_str.startswith("reg")) and \
                    (value_str is not None and len(value_str) != 0 and value_str != "None"):
                _add_reg_to_reg_summary(value_str)

        # ---------------------------------------------------------------------------
        # pt extra info
        if extrainfo is not None:
            _pt_log(">>>           : %-50s: %s" % (" ", extrainfo))


def _xrk_api_invoke_retn_detail(dbg, api_name, ret_dict=None, extrainfo=None):
    """
        print api call retn info

        @param: api_name  : string :
        @param: ret_dict  : dict   : (optional, dft=None)retn dict
        @param: extrainfo : string :
    """
    # temp assert
    if ret_dict is not None:
        assert type(ret_dict) is dict

    # at least 1 param shall be valid
    assert not (ret_dict is None and extrainfo is None)

    api_name_retn = api_name + "_ret"

    if ret_dict is None:

        assert extrainfo is not None
        _pt_log(">>> api_invoke: (%.8X)%-40s: %s" % (dbg.dbg.dwThreadId, api_name_retn, extrainfo))

    else:

        assert len(ret_dict) != 0
        has_pt_first_retn = False
        for (retn_str, value_str) in ret_dict.items():

            if not has_pt_first_retn:

                _pt_log(">>> api_invoke: (%.8X)%-40s: %-15s: %s" % (dbg.dbg.dwThreadId, api_name_retn, retn_str, value_str))
                has_pt_first_retn = True

            else:
                _pt_log(">>>           : (%.8X)%-50s: %-15s: %s" % (dbg.dbg.dwThreadId, " ", retn_str, value_str))

        if extrainfo is not None:
            # we assuse these 2 lines will pt together.
            _pt_log(">>>           : %-50s: %s" % (" ", extrainfo))


# ---------------------------------------------------------------------------
# handler - special apis


def handler_ret_GetLastError(dbg):
    """
        modify ret
    """
    global v_tmp_last_RtlGetLastWin32Error_ret_value
    assert v_tmp_last_RtlGetLastWin32Error_ret_value is not None

    global v_tmp_is_intrude_debugee
    if v_tmp_is_intrude_debugee:

        _xrk_api_invoke_retn_detail(dbg, "GetLastError", extrainfo="modifying ret value from %d to %d" % (dbg.context.Eax, v_tmp_last_RtlGetLastWin32Error_ret_value))
        dbg.set_register("EAX", v_tmp_last_RtlGetLastWin32Error_ret_value)

    else:
        _xrk_api_invoke_retn_detail(dbg, "GetLastError", extrainfo="intrude debugee not allowed, so we cancel it")

    v_tmp_last_RtlGetLastWin32Error_ret_value = None

    # remove bp, because this is one short
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


# addr to set bp
global v_tmp_ntdll_RtlGetLastWin32Error_ret_addr
v_tmp_ntdll_RtlGetLastWin32Error_ret_addr = 0

# new ret value
global v_tmp_last_RtlGetLastWin32Error_ret_value
v_tmp_last_RtlGetLastWin32Error_ret_value = None


def _set_GetLastError_ret_once(dbg, ret=0):
    """
        DWORD WINAPI GetLastError(void);
    """
    global v_tmp_ntdll_RtlGetLastWin32Error_ret_addr
    if v_tmp_ntdll_RtlGetLastWin32Error_ret_addr == 0:
        addr_RtlGetLastWin32Error = dbg.func_resolve("ntdll.dll", "RtlGetLastWin32Error")
        assert addr_RtlGetLastWin32Error != 0
        # ret offset: 0000FE0A - 0000FE01 = 9
        v_tmp_ntdll_RtlGetLastWin32Error_ret_addr = addr_RtlGetLastWin32Error + 9

    # there shouldn't be any "caching" ret values
    global v_tmp_last_RtlGetLastWin32Error_ret_value
    assert v_tmp_last_RtlGetLastWin32Error_ret_value is None

    dbg.bp_set(v_tmp_ntdll_RtlGetLastWin32Error_ret_addr, handler=handler_ret_GetLastError)

    v_tmp_last_RtlGetLastWin32Error_ret_value = ret


def handler_GetProcAddress(dbg):
    """
        param might be string or int

        kernel32.GetProcAddress

        GetProcAddress-->LdrGetProcedureAddress

          HMODULE hModule,
          LPCWSTR lpProcName
    """
    check = dbg.read_stack_int32(8)

    param_dict = None
    extrainfo = None

    if check > 0x1000:
        # must be ascii string
        proc = dbg.read_stack_p_ascii_string(8, max_bytes=256)
        if proc is not None:

            assert len(proc) != 0
            param_dict = {"proc": proc}

            # add to global manual resolved func list.
            global v_tmp_manual_resolved_funcs
            if proc not in v_tmp_manual_resolved_funcs:
                v_tmp_manual_resolved_funcs.append(proc)

        else:
            extrainfo = "(get param fail, stack var: %.8X)" % check

    if param_dict is None:
        param_dict = {"ordinal": "%d" % check}

    _xrk_api_invoke_detail(dbg, "GetProcAddress", param_dict, extrainfo)
    return param_dict


def handler_RegSetValueExA(dbg):
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
    reg_value = dbg.read_stack_p_ascii_string(8)
    type_ = dbg.read_stack_int32(0x10)
    pdata = dbg.read_stack_int32(0x14)
    data_size = dbg.read_stack_int32(0x18)
    type_str, reg_data = get_reg_data(dbg, type_, pdata, data_size)

    param_dict = {"reg_value": reg_value, "type": type_str, "data": reg_data}
    _xrk_api_invoke_detail(dbg, "RegSetValueExA", param_dict)
    return param_dict


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
    reg_value = dbg.read_stack_p_unicode_string(8)
    type_ = dbg.read_stack_int32(0x10)
    pdata = dbg.read_stack_int32(0x14)
    data_size = dbg.read_stack_int32(0x18)
    type_str, reg_data = get_reg_data(dbg, type_, pdata, data_size)

    param_dict = {"reg_value": reg_value, "type": type_str, "data": reg_data}
    _xrk_api_invoke_detail(dbg, "RegSetValueExW", param_dict)
    return param_dict


v_dict_sock_af = {0: "AF_UNSPEC", 2: "AF_INET", 6: "AF_IPX", 16: "AF_APPLETALK", 17: "AF_NETBIOS", 23: "AF_INET6", 26: "AF_IRDA", 32: "AF_BTH"}
v_dict_sock_type = {1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 4: "SOCK_RDM", 5: "SOCK_SEQPACKET"}
v_dict_sock_protocol = {0: "IPPROTO_RAW", 1: "IPPROTO_ICMP", 2: "IPPROTO_IGMP", 3: "BTHPROTO_RFCOMM", 6: "IPPROTO_TCP", 17: "IPPROTO_UDP", 58: "IPPROTO_ICMPV6", 113: "IPPROTO_RM"}


def handler_ret_WSASocketW(dbg):
    """
        modify result
    """
    global v_tmp_is_all_socket_success
    assert v_tmp_is_all_socket_success is True

    if dbg.context.Eax == 0xFFFFFFFF:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "WSASocketW", extrainfo="force ret from 0xFFFFFFFF to 0")
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "WSASocketW", extrainfo="intrude debugee not allowed, so we cancel it")

    return defines.DBG_CONTINUE


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
    global v_tmp_is_all_socket_success
    if v_tmp_is_all_socket_success:
        # 00004114 - 0000404E = 0xC6
        dbg.bp_set(dbg.context.Eip + 0xC6, handler=handler_ret_WSASocketW)

    af = dbg.read_stack_int32(4)
    type_ = dbg.read_stack_int32(8)
    protocol = dbg.read_stack_int32(0xC)

    af_str = af not in v_dict_sock_af and ("%X" % af) or v_dict_sock_af[af]
    type_str = type_ not in v_dict_sock_type and ("%X" % type_) or v_dict_sock_type[type_]
    protocol_str = protocol not in v_dict_sock_protocol and ("%X" % protocol) or v_dict_sock_protocol[protocol]

    param_dict = {"af": af_str, "type": type_str, "protocol": protocol_str}
    _xrk_api_invoke_detail(dbg, "WSASocketW", param_dict)
    return param_dict


def parse_sockaddr(dbg, addr_ptr):
    """
    """
    p_ip_value = addr_ptr + 0x2 + 0x2
    p_port = addr_ptr + 0x2
    port = socket.ntohs(dbg.read_int16(p_port))
    ip_value = dbg.read_int32(p_ip_value)
    ip_str = socket.inet_ntoa(struct.pack('I', ip_value))
    return ip_str, ip_value, port


def handler_getsockname(dbg):
    """
        parse param

        ws2_32.getsockname

          SOCKET s,
          struct sockaddr FAR* name,
          int FAR* namelen
    """
    p_addr = dbg.read_stack_int32(8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    param_dict = {"addr": "%s:%d" % (ip_str, port)}
    _xrk_api_invoke_detail(dbg, "getsockname", param_dict)
    return param_dict


def handler_ret_gethostname(dbg):
    """
        record result
    """
    global v_tmp_addr_result_gethostname
    assert v_tmp_addr_result_gethostname is not None

    result_str = dbg.read_ascii_string(v_tmp_addr_result_gethostname)
    _xrk_api_invoke_retn_detail(dbg, "gethostname", ret_dict={"host_name": result_str})

    v_tmp_addr_result_gethostname = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_gethostname(dbg):
    """
        record result

        ws2_32.gethostname

          _Out_ char *name,
          _In_  int  namelen
    """
    global v_tmp_addr_result_gethostname
    assert v_tmp_addr_result_gethostname is None

    v_tmp_addr_result_gethostname = dbg.read_stack_int32(4)
    # 00005557 - 00005449 = 0x10E
    dbg.bp_set(dbg.context.Eip + 0x10E, handler=handler_ret_gethostname)

    _xrk_api_invoke_detail(dbg, "gethostname")
    return ""


def parse_hostent(dbg, p_hostent):
    """
        parse struct hostent

        typedef struct hostent {
          char FAR      *h_name;
          char FAR  FAR **h_aliases;
          short         h_addrtype;
          short         h_length;
          char FAR  FAR **h_addr_list;
        } HOSTENT, *PHOSTENT, FAR *LPHOSTENT;
    """
    name = dbg.read_p_ascii_string(p_hostent)
    aliases = dbg.read_pp_ascii_string(p_hostent + 4)

    return "(name:%s)(aliases:%s)(addr:)" % (name, aliases)


def handler_ret_gethostbyname(dbg):
    """
        record results
    """
    p_hostent = dbg.context.Eax
    desc_str = parse_hostent(dbg, p_hostent)

    _xrk_api_invoke_retn_detail(dbg, "gethostbyname", ret_dict={"host": desc_str})

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_gethostbyname(dbg):
    """
        record results

        ws2_32.gethostbyname

          _In_ const char *name
    """
    name = dbg.read_stack_p_ascii_string(4)

    # 00005441 - 00005355 = 0xEC
    dbg.bp_set(dbg.context.Eip + 0xEC, handler=handler_ret_gethostbyname)

    param_dict = {"name": name}
    _xrk_api_invoke_detail(dbg, "gethostbyname", param_dict)
    return param_dict


def handler_ret_bind(dbg):
    """
        modify ret
    """
    global v_tmp_is_all_socket_success
    assert v_tmp_is_all_socket_success is True

    if dbg.context.Eax != 0:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "bind", extrainfo="force ret from %d to 0" % dbg.context.Eax)
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "bind", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_bind(dbg):
    """
        parse param, and modify ret

        ws2_32.bind

          _In_ SOCKET                s,
          _In_ const struct sockaddr *name,
          _In_ int                   namelen
    """
    global v_tmp_is_all_socket_success
    if v_tmp_is_all_socket_success:
        # 000044E3 - 00004480 = 0x63
        dbg.bp_set(dbg.context.Eip + 0x63, handler=handler_ret_bind)

    p_addr = dbg.read_stack_int32(8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    param_dict = {"addr": "%s:%d" % (ip_str, port)}
    _xrk_api_invoke_detail(dbg, "bind", param_dict)
    return param_dict


def handler_ret_connect(dbg):
    """
        modify ret
    """
    global v_tmp_is_all_socket_success
    assert v_tmp_is_all_socket_success is True

    if dbg.context.Eax != 0:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "connect", extrainfo="force ret from %d to 0" % dbg.context.Eax)
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "connect", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_connect(dbg):
    """
        param param, and modify ret

        ws2_32.connect

          SOCKET s,
          const struct sockaddr FAR* name,
          int namelen
    """
    global v_tmp_is_all_socket_success
    if v_tmp_is_all_socket_success:
        # 00004A7B - 00004A07 = 0x74
        dbg.bp_set(dbg.context.Eip + 0x74, handler=handler_ret_connect)

    p_addr = dbg.read_stack_int32(8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    param_dict = {"addr": "%s:%d" % (ip_str, port)}
    extrainfo = None

    global v_tmp_new_sock_connect_ip
    if v_tmp_new_sock_connect_ip is not None:

        assert len(v_tmp_new_sock_connect_ip) == 4
        dbg.write(p_addr + 4, v_tmp_new_sock_connect_ip, 4)
        extrainfo = ">>> modified to some new address <<<"

    global v_tmp_new_sock_connect_port
    if v_tmp_new_sock_connect_port is not None and port != v_tmp_new_sock_connect_port:

        assert v_tmp_new_sock_connect_port > 0 and v_tmp_new_sock_connect_port < 65535
        dbg.write_int16(p_addr + 2, v_tmp_new_sock_connect_port)
        extrainfo_x = ">>> modified to some new port <<<"
        extrainfo = extrainfo is None and extrainfo_x or extrainfo + extrainfo_x

    _xrk_api_invoke_detail(dbg, "connect", param_dict, extrainfo)
    return param_dict


def handler_ret_WSAConnect(dbg):
    """
        modify ret
    """
    global v_tmp_is_all_socket_success
    assert v_tmp_is_all_socket_success is True

    if dbg.context.Eax != 0:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "WSAConnect", extrainfo="force ret from %d to 0" % dbg.context.Eax)
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "WSAConnect", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


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
    global v_tmp_is_all_socket_success
    if v_tmp_is_all_socket_success:
        # 00010D13 - 00010C81 = 0x92
        dbg.bp_set(dbg.context.Eip + 0x92, handler=handler_ret_WSAConnect)

    p_addr = dbg.read_stack_int32(8)
    ip_str, ip_value, port = parse_sockaddr(dbg, p_addr)

    param_dict = {"addr": "%s:%d" % (ip_str, port)}
    extrainfo = None

    global v_tmp_new_sock_connect_ip
    if v_tmp_new_sock_connect_ip is not None:

        assert len(v_tmp_new_sock_connect_ip) == 4
        dbg.write(p_addr + 4, v_tmp_new_sock_connect_ip, 4)
        extrainfo = ">>> modified to some new address <<<"

    global v_tmp_new_sock_connect_port
    if v_tmp_new_sock_connect_port is not None and port != v_tmp_new_sock_connect_port:

        assert v_tmp_new_sock_connect_port > 0 and v_tmp_new_sock_connect_port < 65535
        dbg.write_int16(p_addr + 2, v_tmp_new_sock_connect_port)
        extrainfo_x = ">>> modified to some new port <<<"
        extrainfo = extrainfo is None and extrainfo_x or extrainfo + extrainfo_x

    _xrk_api_invoke_detail(dbg, "WSAConnect", param_dict, extrainfo)
    return param_dict


def handler_send(dbg):
    """
        save send data

        ws2_32.send

          _In_       SOCKET s,
          _In_ const char   *buf,
          _In_       int    len,
          _In_       int    flags
    """
    addr = dbg.read_stack_int32(8)
    len_ = dbg.read_stack_int32(0xC)

    global v_tmp_is_save_send_data_to_file
    if v_tmp_is_save_send_data_to_file:
        data = dbg.read(addr, len_)
        util.save_buf_to_file("send", data)

    param_dict = {"addr": "%.8X" % addr, "len": "%.8X" % len_}
    _xrk_api_invoke_detail(dbg, "send", param_dict)
    return param_dict


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
    addr = dbg.read_stack_int32(8)
    len_ = dbg.read_stack_int32(0xC)

    global v_tmp_is_save_send_data_to_file
    if v_tmp_is_save_send_data_to_file:
        data = dbg.read(addr, len_)
        util.save_buf_to_file("sendto", data)

    param_dict = {"addr": "%.8X" % addr, "len": "%.8X" % len_}
    _xrk_api_invoke_detail(dbg, "sendto", param_dict)
    return param_dict


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
    buf_array = dbg.read_stack_int32(8)
    buf_cnt = dbg.read_stack_int32(0xC)

    global v_tmp_is_save_send_data_to_file

    size = 0
    for i in range(buf_cnt):

        len_i = dbg.read_int32(buf_array + i * 8)  # 8 is size of WSABUF structure
        buf_i = dbg.read_int32(buf_array + i * 8 + 4)

        size = size + len_i

        if v_tmp_is_save_send_data_to_file:
            data_i = dbg.read(buf_i, len_i)
            util.save_buf_to_file("WASSend_%d" % i, data_i)

    param_dict = {"buf_cnt": "%d" % buf_cnt, "size_send": "%.8X" % size}
    _xrk_api_invoke_detail(dbg, "WSASend", param_dict)
    return param_dict


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
    buf_array = dbg.read_stack_int32(8)
    buf_cnt = dbg.read_stack_int32(0xC)

    global v_tmp_is_save_send_data_to_file

    size = 0
    for i in range(buf_cnt):

        len_i = dbg.read_int32(buf_array + i * 8)  # 8 is size of WSABUF structure
        buf_i = dbg.read_int32(buf_array + i * 8 + 4)

        size = size + len_i

        if v_tmp_is_save_send_data_to_file:
            data_i = dbg.read(buf_i, len_i)
            util.save_buf_to_file("WSASendTo_%d" % i, data_i)

    param_dict = {"buf_cnt": "%d" % buf_cnt, "size_sendto": "%.8X" % size}
    _xrk_api_invoke_detail(dbg, "WSASendTo", param_dict)
    return param_dict


def handler_ret_recv(dbg):
    """
        save result
    """
    global v_tmp_addr_result_recv
    assert v_tmp_addr_result_recv is not None

    len_ = dbg.context.Eax
    _xrk_api_invoke_retn_detail(dbg, "recv", ret_dict={"size_recved": "%d" % len_})

    global v_tmp_is_save_recv_data_to_file
    if v_tmp_is_save_recv_data_to_file:
        data = dbg.read(v_tmp_addr_result_recv, len_)
        util.save_buf_to_file("recv", data)

    v_tmp_addr_result_recv = None
    dbg.bp_del(dbg.context.Eip)
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
    result_addr = dbg.read_stack_int32(8)

    global v_tmp_addr_result_recv
    assert v_tmp_addr_result_recv is None

    v_tmp_addr_result_recv = result_addr

    # 00006800 - 0000676F = 0x91
    dbg.bp_set(dbg.context.Eip + 0x91, handler=handler_ret_recv)

    _xrk_api_invoke_detail(dbg, "recv")
    return ""


def handler_ret_recvfrom(dbg):
    """
        save result
    """
    global v_tmp_addr_result_recv
    assert v_tmp_addr_result_recv is not None

    len_ = dbg.context.Eax
    _xrk_api_invoke_retn_detail(dbg, "recvfrom", ret_dict={"recved_len": "%d" % len_})

    global v_tmp_is_save_recv_data_to_file
    if v_tmp_is_save_recv_data_to_file:
        data = dbg.read(v_tmp_addr_result_recv, len_)
        util.save_buf_to_file("recvfrom", data)

    v_tmp_addr_result_recv = None
    dbg.bp_del(dbg.context.Eip)
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
    result_addr = dbg.read_stack_int32(8)

    global v_tmp_addr_result_recv
    assert v_tmp_addr_result_recv is None

    v_tmp_addr_result_recv = result_addr

    # 000030A0 - 00002FF7 = 0xA9
    dbg.bp_set(dbg.context.Eip + 0xA9, handler=handler_ret_recvfrom)

    _xrk_api_invoke_detail(dbg, "recvfrom")
    return ""


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
    _xrk_api_invoke_detail(dbg, "WSARecv")
    return ""


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
    _xrk_api_invoke_detail(dbg, "WSARecvFrom")
    return ""


def handler_ret_select(dbg):
    """
        modify ret
    """
    global v_tmp_is_all_socket_success
    assert v_tmp_is_all_socket_success is True

    if dbg.context.Eax == 0xFFFFFFFF or dbg.context.Eax == 0:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "select", extrainfo="force ret from %d to 1" % dbg.context.Eax)
            dbg.set_register("EAX", 1)

        else:
            _xrk_api_invoke_retn_detail(dbg, "select", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.bp_del(dbg.context.Eip)
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
    global v_tmp_is_all_socket_success
    if v_tmp_is_all_socket_success:
        # 00003168 - 000030A8 = 0xC0
        dbg.bp_set(dbg.context.Eip + 0xC0, handler=handler_ret_select)

    _xrk_api_invoke_detail(dbg, "select")
    return ""


def handler_ret_setsockopt(dbg):
    """
        modify ret
    """
    global v_tmp_is_all_socket_success
    assert v_tmp_is_all_socket_success is True

    if dbg.context.Eax != 0:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "setsockopt", extrainfo="force ret from %d to 0" % dbg.context.Eax)
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "setsockopt", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.bp_del(dbg.context.Eip)
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
    global v_tmp_is_all_socket_success
    if v_tmp_is_all_socket_success:
        # 000045AD - 00004521 = 0x8C
        dbg.bp_set(dbg.context.Eip + 0x8C, handler=handler_ret_setsockopt)

    _xrk_api_invoke_detail(dbg, "setsockopt")
    return ""


def parse_internetbuf(dbg, p_buf):
    """
        typedef struct _INTERNET_BUFFERS {
          DWORD             dwStructSize;
          _INTERNET_BUFFERS *Next;
          LPCTSTR           lpcszHeader;
          DWORD             dwHeadersLength;
          DWORD             dwHeadersTotal;
          LPVOID            lpvBuffer;
          DWORD             dwBufferLength;
          DWORD             dwBufferTotal;
          DWORD             dwOffsetLow;
          DWORD             dwOffsetHigh;
        } INTERNET_BUFFERS, * LPINTERNET_BUFFERS;
    """
    # for now, we only parse first buffer, even if more buffer is available
    header = dbg.read_p_ascii_string(p_buf + 8)
    buf = dbg.read_int32(p_buf + 0x14)
    len_ = dbg.read_int32(p_buf + 0x18)

    return (header, buf, len_)


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
    svr = dbg.read_stack_p_ascii_string(8)
    user_name = dbg.read_stack_p_ascii_string(0x10)
    user_pwd = dbg.read_stack_p_ascii_string(0x14)

    extrainfo = None
    global v_tmp_new_http_connect_addr
    if v_tmp_new_http_connect_addr is not None:
        dbg.write_stack_p_ascii_string(8, v_tmp_new_http_connect_addr)
        extrainfo = ">>> new http connect svr: %s <<<" % v_tmp_new_http_connect_addr

    param_dict = {"svr": svr, "user_name": user_name, "user_pwd": user_pwd}
    _xrk_api_invoke_detail(dbg, "InternetConnectA", param_dict, extrainfo)
    return param_dict


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
    p_buf = dbg.read_stack_int32(8)
    header, buf, len_ = parse_internetbuf(dbg, p_buf)

    param_dict = {"header": header, "buf": "%.8X" % buf, "size_httpsend": "%.8X" % len_}
    _xrk_api_invoke_detail(dbg, "HttpSendRequestExA", param_dict)
    return param_dict


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
    p_buf = dbg.read_stack_int32(8)
    header, buf, len_ = parse_internetbuf(dbg, p_buf)

    param_dict = {"header": header, "buf": "%.8X" % buf, "size_httpsend": "%.8X" % len_}
    _xrk_api_invoke_detail(dbg, "HttpSendRequestExW", param_dict)
    return param_dict


def handler_ret_WinHttpCreateUrl(dbg):
    """
        record result url
    """
    global v_tmp_addr_result_WinHttpCreateUrl
    assert v_tmp_addr_result_WinHttpCreateUrl is not None

    ret_url = dbg.read_unicode_string(v_tmp_addr_result_WinHttpCreateUrl)

    _xrk_api_invoke_retn_detail(dbg, "WinHttpCreateUrl", ret_dict={"ret_url": ret_url})

    v_tmp_addr_result_WinHttpCreateUrl = None

    global v_tmp_addr_WinHttpCreateUrl_rets
    assert v_tmp_addr_WinHttpCreateUrl_rets is not None and len(v_tmp_addr_WinHttpCreateUrl_rets) == 8
    for ret_addr in v_tmp_addr_WinHttpCreateUrl_rets:
        dbg.bp_del(ret_addr)

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
    result_addr = dbg.read_stack_int32(0xC)

    global v_tmp_addr_result_WinHttpCreateUrl
    assert v_tmp_addr_result_WinHttpCreateUrl is None

    v_tmp_addr_result_WinHttpCreateUrl = result_addr

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
    global v_tmp_addr_WinHttpCreateUrl_rets
    if v_tmp_addr_WinHttpCreateUrl_rets is None:
        v_tmp_addr_WinHttpCreateUrl_rets = []
        for offset in offsets:
            v_tmp_addr_WinHttpCreateUrl_rets.append(dbg.context.Eip + offset)

    for ret_addr in v_tmp_addr_WinHttpCreateUrl_rets:
        dbg.bp_set(ret_addr, handler=handler_ret_WinHttpCreateUrl)

    _xrk_api_invoke_detail(dbg, "WinHttpCreateUrl")
    return ""


def _check_if_data_is_pe(dbg, buf, api_name):
    """
        @param: buf      : int    : address
        @param: api_name : string : api name

        @return: string : as extra info
               : None   :
    """
    f2 = dbg.read(buf, 2)
    if len(f2) == 2:
        if f2[0] == b"\x4D" and f2[1] == b"\x5A":
            return ">>> PE Header <<<"
            # todo: check if is full pe, and save it if it is.
    else:
        return "get first 2 bytes fail"


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
    buf = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0xC)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, buf, "WinHttpWriteData")

    param_dict = {"buf": "%.8X" % buf, "size_httpwrite": "%.8X" % size}
    _xrk_api_invoke_detail(dbg, "WinHttpWriteData", param_dict, extrainfo)
    return param_dict


def _pid_to_procname(dbg, pid):
    """
    """
    if pid == dbg.pid:
        return "[Debugee]"
    else:
        return "%d-%s" % (pid, util.pid_to_proc_path(pid))


def h_proc_to_proc_str(dbg, h_proc):
    """
        convert process handle from debugee to process info string

        @param: h_proc : HANDLE : process handle available only for debugee. we need to duplicat it first.

        @return: string :
               : None   :
    """
    h_proc_my = dbg.duplicate_handle(h_proc)
    if not h_proc_my:
        return None

    else:
        pid = ctypes.windll.kernel32.GetProcessId(h_proc_my)
        ctypes.windll.kernel32.CloseHandle(h_proc_my)

        return _pid_to_procname(dbg, pid)


def h_file_to_file_str(dbg, h_file):
    """
        convert file handle from debugee to file info string

        @param: h_file : HANDLE : file handle available only for debugee. we need to duplicat it first.

        @return: string :
               : None   :
    """
    if h_file == 0xFFFFFFFF:
        _pt_log(">>> invalid file handle: 0xFFFFFFFF")
        return None

    h_file_my = dbg.duplicate_handle(h_file)
    if not h_file_my:
        return None

    else:
        ret = None

        file_map = ctypes.windll.kernel32.CreateFileMappingA(h_file_my, 0, defines.PAGE_READONLY, 0, 1, 0)
        if file_map:
            # map a single byte of the file into memory so we can query for the file name.
            ctypes.windll.kernel32.MapViewOfFile.restype = ctypes.POINTER(ctypes.c_char)
            file_ptr = ctypes.windll.kernel32.MapViewOfFile(file_map, defines.FILE_MAP_READ, 0, 0, 1)

            if file_ptr:
                # query for the filename of the mapped file.
                filename = ctypes.create_string_buffer(2048)
                ctypes.windll.psapi.GetMappedFileNameA(ctypes.windll.kernel32.GetCurrentProcess(), file_ptr, ctypes.byref(filename), 2048)

                # store the full path. this is kind of ghetto, but i didn't want to mess with QueryDosDevice() etc ...
                ret = (os.sep + filename.value.split(os.sep, 3)[3]).lower()

                ctypes.windll.kernel32.UnmapViewOfFile(file_ptr)

            ctypes.windll.kernel32.CloseHandle(file_map)

        ctypes.windll.kernel32.CloseHandle(h_file_my)
        return ret


def handler_IsWow64Process(dbg):
    """
        parse params

        kernel32.IsWow64Process

        IsWow64Process-->NtQueryInformationProcess(ntdll)

          _In_  HANDLE hProcess,
          _Out_ PBOOL  Wow64Process
    """
    h_proc = dbg.read_stack_int32(4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    param_dict = {"proc": h_proc_str}
    _xrk_api_invoke_detail(dbg, "IsWow64Process", param_dict)
    return param_dict


def handler_ret_CreateProcessInternalW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_CreateProcessInternalW
    assert v_tmp_addr_result_CreateProcessInternalW is not None

    pid = dbg.read_int32(v_tmp_addr_result_CreateProcessInternalW + 8)
    _xrk_api_invoke_retn_detail(dbg, "CreateProcessInternalW", ret_dict={"ret_pid": "%d" % pid})

    v_tmp_addr_result_CreateProcessInternalW = None
    dbg.bp_del(dbg.context.Eip)
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
    app_name = dbg.read_stack_p_unicode_string(8)
    cmd_line = dbg.read_stack_p_unicode_string(0xC)
    cur_dir_ = dbg.read_stack_p_unicode_string(0x24)

    if app_name is not None:
        _add_proc_to_proc_summary("%s %s" % (app_name, cmd_line))
    else:
        _add_proc_to_proc_summary(cmd_line)

    global v_tmp_addr_result_CreateProcessInternalW
    assert v_tmp_addr_result_CreateProcessInternalW is None
    v_tmp_addr_result_CreateProcessInternalW = dbg.read_stack_int32(0x2C)
    # 0001A04D - 0001979C = 0x8B1
    dbg.bp_set(dbg.context.Eip + 0x8B1, handler=handler_ret_CreateProcessInternalW)

    param_dict = {"app_name": app_name, "cmd_line": cmd_line, "cur_dir": cur_dir_}
    _xrk_api_invoke_detail(dbg, "CreateProcessInternalW", param_dict)
    return param_dict


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
    h_proc = dbg.read_stack_int32(4)
    cbk = dbg.read_stack_int32(0x10)

    if h_proc != 0xFFFFFFFF:

        h_proc_str = h_proc_to_proc_str(dbg, h_proc)
        param_dict = {"proc": h_proc_str, "cbk": "%.8X" % cbk}
        _xrk_api_invoke_detail(dbg, "CreateRemoteThread", param_dict, "create remote thread in another process!!")
        return param_dict

    else:
        param_dict = {"cbk": "%.8X" % cbk}
        _xrk_api_invoke_detail(dbg, "CreateThread", param_dict)
        return param_dict


def handler_OpenProcess(dbg):
    """
        parse params

        kernel32.OpenProcess

        OpenProcess-->NtOpenProcess(ntdll)

          _In_ DWORD dwDesiredAccess,
          _In_ BOOL  bInheritHandle,
          _In_ DWORD dwProcessId
    """
    pid = dbg.read_stack_int32(0xC)
    proc_path = util.pid_to_proc_path(pid)

    param_dict = {"pid": "%d" % pid, "proc": proc_path}
    _xrk_api_invoke_detail(dbg, "OpenProcess", param_dict)
    return param_dict


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

        global v_tmp_is_normal_termination
        v_tmp_is_normal_termination = True

    else:
        h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    param_dict = {"proc": h_proc_str, "code": "%d" % code}
    _xrk_api_invoke_detail(dbg, "TerminateProcess", param_dict)
    return param_dict


def handler_ExitProcess(dbg):
    """
        update global var

        kernel32.ExitProcess

        ExitProcess-->LdrShutdownProcess

          _In_ UINT uExitCode
    """
    code = dbg.read_stack_int32(4)

    global v_tmp_is_normal_termination
    v_tmp_is_normal_termination = True

    param_dict = {"code": "%d" % code}
    _xrk_api_invoke_detail(dbg, "ExitProcess", param_dict)
    return param_dict


def handler_GetExitCodeProcess(dbg):
    """
        parse params

        kernel32.GetExitCodeProcess

        GetExitCodeProcess-->NtQueryInformationProcess(ntdll)

          _In_   HANDLE hProcess,
          _Out_  LPDWORD lpExitCode
    """
    h_proc = dbg.read_stack_int32(4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    param_dict = {"proc": h_proc_str}
    _xrk_api_invoke_detail(dbg, "GetExitCodeProcess", param_dict)
    return param_dict


def parse_context(dbg, p_ctx):
    """
        parse context

        @return: tuple : (flags, flags_str)
    """
    flags = dbg.read_int32(p_ctx)

    flags_str = ""
    if flags & 0x00010001:
        flags_str = flags_str + "|CONTEXT_CONTROL"
    if flags & 0x00010007:
        flags_str = flags_str + "|CONTEXT_FULL"
    if flags & 0x00010010:
        flags_str = flags_str + "|CONTEXT_DEBUG_REGISTERS"

    if len(flags_str) == 0:
        flags_str = "NotRecoginized"
    else:
        flags_str = flags_str.strip("|")

    return (flags, flags_str)


def handler_SetThreadContext(dbg):
    """
        parse params
    """
    p_ctx = dbg.read_stack_int32(8)
    flags, flags_str = parse_context(dbg, p_ctx)

    param_dict = {"flags": "%.8X-%s" % (flags, flags_str)}
    _xrk_api_invoke_detail(dbg, "SetThreadContext", param_dict)
    return param_dict


def handler_GetThreadContext(dbg):
    """
        parse params
    """
    p_ctx = dbg.read_stack_int32(8)
    flags, flags_str = parse_context(dbg, p_ctx)

    param_dict = {"flags": "%.8X-%s" % (flags, flags_str)}
    _xrk_api_invoke_detail(dbg, "GetThreadContext", param_dict)
    return param_dict


def handler_CreateToolhelp32Snapshot(dbg):
    """
        parse params

        kernel32.CreateToolhelp32Snapshot

          _In_ DWORD dwFlags,
          _In_ DWORD th32ProcessID
    """
    flags = dbg.read_stack_int32(4)
    pid = dbg.read_stack_int32(8)
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

    param_dict = {"flags": flags_str, "proc": proc_path}
    _xrk_api_invoke_detail(dbg, "CreateToolhelp32Snapshot", param_dict)
    return param_dict


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
    base = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0x10)
    h_proc = dbg.read_stack_int32(4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    # todo: we might need to record results

    param_dict = {"proc": h_proc_str, "base": "%.8X" % base, "size_read_from_proc": "%.8X" % size}
    _xrk_api_invoke_detail(dbg, "ReadProcessMemory", param_dict)
    return param_dict


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
    base = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0x10)
    h_proc = dbg.read_stack_int32(4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, base, "WriteProcessMemory")

    param_dict = {"proc": h_proc_str, "base": "%.8X" % base, "size_write_to_proc": "%.8X" % size}
    _xrk_api_invoke_detail(dbg, "WriteProcessMemory", param_dict, extrainfo)
    return param_dict


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
    h_file = dbg.read_stack_int32(4)
    if h_file == 0xFFFFFFFF:
        file_str = "[system_paging]"

    else:
        file_str = h_file_to_file_str(dbg, h_file)

    file_opt = dbg.read_stack_p_unicode_string(0x18)

    param_dict = {"file": file_str, "file_opt": file_opt}
    _xrk_api_invoke_detail(dbg, "CreateFileMappingW", param_dict)
    return param_dict


def handler_UnmapViewOfFile(dbg):
    """
        check if buf has PE header

        kernel32.UnmapViewOfFile

        UnmapViewOfFile-->NtUnmapViewOfSection

          LPCVOID lpBaseAddress
    """
    addr = dbg.read_stack_int32(4)

    extrainfo = _check_if_data_is_pe(dbg, addr, "UnmapViewOfFile")

    param_dict = {"addr": "%.8X" % addr}
    _xrk_api_invoke_detail(dbg, "UnmapViewOfFile", param_dict, extrainfo)
    return param_dict


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
    file = dbg.read_stack_p_unicode_string(4)
    # todo: parse these 2 params
    # access = dbg.read_stack_int32(8)
    # mode = dbg.read_stack_int32(0xC)

    param_dict = {"file": file}
    _xrk_api_invoke_detail(dbg, "CreateFileW", param_dict)
    return param_dict


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
    buf = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0xC)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, buf, "WriteFile")

    param_dict = {"buf": "%.8X" % buf, "size_write_file": "%.8X" % size}
    _xrk_api_invoke_detail(dbg, "WriteFile", param_dict, extrainfo)
    return param_dict


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
    buf = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0xC)

    extrainfo = None
    if size >= 2:
        extrainfo = _check_if_data_is_pe(dbg, buf, "WriteFileEx")

    param_dict = {"buf": "%.8X" % buf, "size_write_file_ex": "%.8X" % size}
    _xrk_api_invoke_detail(dbg, "WriteFileEx", param_dict, extrainfo)
    return param_dict


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
    file_old = dbg.read_stack_p_unicode_string(4)
    file_new = dbg.read_stack_p_unicode_string(8)
    flags = dbg.read_stack_int32(0x14)

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

    param_dict = {"file_old": file_old, "file_new": file_new, "flags": flags_str}
    _xrk_api_invoke_detail(dbg, "MoveFileWithProgressW", param_dict, extrainfo)
    return param_dict


def handler_RemoveDirectoryW(dbg):
    """
        might backup dir

        kernel32.RemoveDirectoryW

        RemoveDirectoryA-->RemoveDirectoryW-->NtOpenFile/NtSetInformationFile(ntdll)

          LPCTSTR lpPathName
    """
    dir_ = dbg.read_stack_p_unicode_string(4)

    global v_tmp_is_backup_remove_dir_file
    if v_tmp_is_backup_remove_dir_file:
        pass

    param_dict = {"dir": dir_}
    _xrk_api_invoke_detail(dbg, "RemoveDirectoryW", param_dict)
    return param_dict


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
    file_replaced = dbg.read_stack_p_unicode_string(4)
    file_replacement = dbg.read_stack_p_unicode_string(8)
    file_backup = dbg.read_stack_p_printable_string(0xC)

    global v_tmp_is_backup_remove_dir_file
    if v_tmp_is_backup_remove_dir_file:
        # todo: backup file
        pass

    param_dict = {"file_replaced": file_replaced, "file_replacement": file_replacement, "file_backup": file_backup}
    _xrk_api_invoke_detail(dbg, "ReplaceFileW", param_dict)
    return param_dict


def handler_DeleteFileW(dbg):
    """
        backup file

        kernel32.DeleteFileW

        DeleteFileA-->DeleteFileW-->NtOpenFile(ntdll)

          LPCTSTR lpFileName
    """
    file = dbg.read_stack_p_unicode_string(4)

    global v_tmp_is_backup_remove_dir_file
    if v_tmp_is_backup_remove_dir_file:
        # todo: backup file
        pass

    param_dict = {"file": file}
    _xrk_api_invoke_detail(dbg, "DeleteFileW", param_dict)
    return param_dict


def handler_SetFileAttributesW(dbg):
    """
        parse attribute

        kernel32.SetFileAttributesW

        SetFileAttributesA-->SetFileAttributesW-->NtOpenFile/NtSetInformationFile(ntdll)

          LPCTSTR lpFileName,
          DWORD dwAttributes
    """
    file = dbg.read_stack_p_unicode_string(4)

    attr = dbg.read_stack_int32(8)

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

    param_dict = {"file": file, "attr_str": attr_str}
    _xrk_api_invoke_detail(dbg, "SetFileAttributesW", param_dict)
    return param_dict


def _read_FILETIME(dbg, p_file_time):
    """
        @param: p_file_time : int : address of defines.FILETIME structure

        @return: defines.FILETIME :
    """
    ret = defines.FILETIME()
    ret.dwLowDateTime = dbg.read_int32(p_file_time)
    ret.dwHighDateTime = dbg.read_int32(p_file_time + 4)
    return ret


def _file_time_to_sys_time_param_str(file_time):
    """
        @param: file_time : obj : defines.FILETIME()

        @return: string :
               : None   :
    """
    sys_time = defines.SYSTEMTIME()
    if ctypes.windll.kernel32.FileTimeToSystemTime(ctypes.byref(file_time), ctypes.byref(sys_time)):
        return _sys_time_to_str(sys_time)
    return None


def _sys_time_to_str(sys_time):
    """
        @param: sys_time : obj : defines.SYSTEMTIME()

        @return: string :
    """
    return "%.4d-%.2d-%.2d-%.2d:%.2d:%.2d:%.3d" % (sys_time.wYear, sys_time.wMonth, sys_time.wDay, sys_time.wHour, sys_time.wMinute, sys_time.wSecond, sys_time.wMilliseconds)


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
    p_time_create = dbg.read_stack_int32(8)
    p_time_last_access = dbg.read_stack_int32(0xC)
    p_time_last_write = dbg.read_stack_int32(0x10)

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

    param_dict = {"time_create": time_create, "time_last_access": time_last_access, "time_last_write": time_last_write}
    _xrk_api_invoke_detail(dbg, "SetFileTime", param_dict)
    return param_dict


def handler_ret_GetFullPathNameW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetFullPathNameW
    assert v_tmp_addr_result_GetFullPathNameW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetFullPathNameW)
    _xrk_api_invoke_retn_detail(dbg, "GetFullPathNameW", ret_dict={"ret_path": result_str})

    v_tmp_addr_result_GetFullPathNameW = None
    dbg.bp_del(dbg.context.Eip)
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
    file = dbg.read_stack_p_unicode_string(4)
    result_addr = dbg.read_stack_int32(0xC)

    global v_tmp_addr_result_GetFullPathNameW
    assert v_tmp_addr_result_GetFullPathNameW is None

    v_tmp_addr_result_GetFullPathNameW = result_addr

    # 0000B8FF - 0000B8E2 = 0x1D
    dbg.bp_set(dbg.context.Eip + 0x1D, handler=handler_ret_GetFullPathNameW)

    param_dict = {"file": file}
    _xrk_api_invoke_detail(dbg, "GetFullPathNameW", param_dict)
    return param_dict


def svc_type_to_str(access_code):
    """
        parse svc type
    """
    ret = ""

    if access_code & 0x00000004:
        ret = ret + "|SERVICE_ADAPTER"
    if access_code & 0x00000002:
        ret = ret + "|SERVICE_FILE_SYSTEM_DRIVER"
    if access_code & 0x00000001:
        ret = ret + "|SERVICE_KERNEL_DRIVER"
    if access_code & 0x00000008:
        ret = ret + "|SERVICE_RECOGNIZER_DRIVER"
    if access_code & 0x00000010:
        ret = ret + "|SERVICE_WIN32_OWN_PROCESS"
    if access_code & 0x00000020:
        ret = ret + "|SERVICE_WIN32_SHARE_PROCESS"
    if access_code & 0x00000100:
        ret = ret + "|SERVICE_INTERACTIVE_PROCESS"

    return ret.strip("|")


def start_type_to_str(start_type):
    """
        parse svc start type
    """
    ret = ""

    if start_type & 0x00000002:
        ret = ret + "|SERVICE_AUTO_START"
    if start_type & 0x00000003:
        ret = ret + "|SERVICE_DEMAND_START"
    if start_type & 0x00000004:
        ret = ret + "|SERVICE_DISABLED"
    if start_type & 0x00000001:
        ret = ret + "|SERVICE_SYSTEM_START"

    if len(ret) == 0:
        ret = "SERVICE_BOOT_START"
    else:
        ret = ret.strip("|")

    return ret


def error_ctrl_to_str(error_ctrl):
    """
        parse svc error ctrl code
    """
    ret = ""

    if error_ctrl & 0x00000002:
        ret = ret + "|SERVICE_ERROR_SEVERE"
    if error_ctrl & 0x00000003:
        ret = ret + "|SERVICE_ERROR_CRITICAL"
    if error_ctrl & 0x00000001:
        ret = ret + "|SERVICE_ERROR_NORMAL"

    if len(ret) == 0:
        ret = "SERVICE_ERROR_IGNORE"
    else:
        ret = ret.strip("|")

    return ret


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
    name_svc = dbg.read_stack_p_ascii_string(8)
    name_display = dbg.read_stack_p_ascii_string(0xC)
    svc_type = dbg.read_stack_int32(0x14)
    start_type = dbg.read_stack_int32(0x18)
    error_ctrl = dbg.read_stack_int32(0x1C)
    bin_path = dbg.read_stack_p_ascii_string(0x20)
    load_order_group = dbg.read_stack_p_ascii_string(0x24)

    svc_type_str = svc_type_to_str(svc_type)
    start_type_str = start_type_to_str(start_type)
    error_str = error_ctrl_to_str(error_ctrl)

    param_dict = {"name": name_svc, "display": name_display, "svc_type": svc_type_str, "start_type": start_type_str,
                  "error": error_str, "file_bin": bin_path, "load_order_group": load_order_group}
    _xrk_api_invoke_detail(dbg, "CreateServiceA", param_dict)
    return param_dict


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
    name_svc = dbg.read_stack_p_unicode_string(8)
    name_display = dbg.read_stack_p_unicode_string(0xC)
    svc_type = dbg.read_stack_int32(0x14)
    start_type = dbg.read_stack_int32(0x18)
    error_ctrl = dbg.read_stack_int32(0x1C)
    bin_path = dbg.read_stack_p_unicode_string(0x20)
    load_order_group = dbg.read_stack_p_unicode_string(0x24)

    svc_type_str = svc_type_to_str(svc_type)
    start_type_str = start_type_to_str(start_type)
    error_str = error_ctrl_to_str(error_ctrl)

    param_dict = {"name": name_svc, "display": name_display, "svc_type": svc_type_str, "start_type": start_type_str,
                  "error": error_str, "file_bin": bin_path, "load_order_group": load_order_group}
    _xrk_api_invoke_detail(dbg, "CreateServiceW", param_dict)
    return param_dict


def handler_ControlService(dbg):
    """
        parse params

        advapi32.ControlService

        ControlService-->RControlService

          _In_  SC_HANDLE        hService,
          _In_  DWORD            dwControl,
          _Out_ LPSERVICE_STATUS lpServiceStatus
    """
    code = dbg.read_stack_int32(8)

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

    param_dict = {"code": code_str}
    if code == 0x1:
        _xrk_api_invoke_detail(dbg, "ControlService", param_dict, "pay attention: sample might stop svc then replace binary by setting reg then start svc again.")
    else:
        _xrk_api_invoke_detail(dbg, "ControlService", param_dict)
    return param_dict


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
    ptable = dbg.read_stack_int32(4)
    svc_name = dbg.read_ascii_string(ptable)
    cbk = dbg.read_int32(ptable + 4)

    param_dict = {"svc": svc_name, "cbk": cbk}
    _xrk_api_invoke_detail(dbg, "StartServiceCtrlDispatcherA", param_dict)
    return param_dict


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
    ptable = dbg.read_stack_int32(4)
    svc_name = dbg.read_unicode_string(ptable)
    cbk = dbg.read_int32(ptable + 4)

    param_dict = {"svc": svc_name, "cbk": cbk}
    _xrk_api_invoke_detail(dbg, "StartServiceCtrlDispatcherW", param_dict)
    return param_dict


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

    param_dict = {"alertable": "%d" % alertable, "msecs": "%d" % msecs}

    if msecs >= 20:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_detail(dbg, "SleepEx", param_dict, "brute force new sleep msecs: %d -> %d" % (msecs, 1))
            dbg.write_stack_int32(4, 1)
            # msecs_new = dbg.read_stack_int32(4)

            # update tick gap
            global v_tmp_fake_tick_gap
            if v_tmp_fake_tick_gap is None:
                v_tmp_fake_tick_gap = msecs
            else:
                v_tmp_fake_tick_gap = v_tmp_fake_tick_gap + msecs

            # update systime gap
            global v_tmp_fake_systime_gap
            if v_tmp_fake_systime_gap is None:
                v_tmp_fake_systime_gap = msecs
            else:
                v_tmp_fake_systime_gap = v_tmp_fake_systime_gap + msecs

        else:
            _xrk_api_invoke_detail(dbg, "SleepEx", param_dict, "intrude debugee not allowed, so we cancel it...")
    else:

        _xrk_api_invoke_detail(dbg, "SleepEx", param_dict)

    return param_dict


def handler_ZwDelayExecution(dbg):
    """
        shorten sleep
    """
    alertable = dbg.read_stack_int32(4)
    msecs = dbg.read_stack_int32(8)

    param_dict = {"alertable": "%d" % alertable, "msecs": "%d" % msecs}
    _xrk_api_invoke_detail(dbg, "ZwDelayExecution", param_dict)
    return param_dict


def handler_NtQueryInformationProcess(dbg):
    """
        parse params
    """
    class_ = dbg.read_stack_int32(8)

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

    param_dict = {"class": "%d-%s" % (class_, class_str)}
    _xrk_api_invoke_detail(dbg, "NtQueryInformationProcess", param_dict)
    return param_dict


def handler_NtQueryInformationThread(dbg):
    """
        parse params
    """
    class_ = dbg.read_stack_int32(8)

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

    param_dict = {"class": "%d-%s" % (class_, class_str)}
    _xrk_api_invoke_detail(dbg, "NtQueryInformationThread", param_dict)
    return param_dict


def handler_NtSetInformationProcess(dbg):
    """
        parse params
    """
    return {}


def handler_ret_ExpandEnvironmentStringsA(dbg):
    """
        record result
    """
    global v_tmp_addr_result_ExpandEnvironmentStringsA
    assert v_tmp_addr_result_ExpandEnvironmentStringsA is not None

    result_str = dbg.read_ascii_string(v_tmp_addr_result_ExpandEnvironmentStringsA)
    _xrk_api_invoke_retn_detail(dbg, "ExpandEnvironmentStringsA", ret_dict={"ret_str": result_str})

    v_tmp_addr_result_ExpandEnvironmentStringsA = None
    dbg.bp_del(dbg.context.Eip)
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
    src = dbg.read_stack_p_ascii_string(4)
    result_addr = dbg.read_stack_int32(8)

    global v_tmp_addr_result_ExpandEnvironmentStringsA
    assert v_tmp_addr_result_ExpandEnvironmentStringsA is None
    v_tmp_addr_result_ExpandEnvironmentStringsA = result_addr

    # 00032AEB - 000329F1 = 0xFA
    dbg.bp_set(dbg.context.Eip + 0xFA, handler=handler_ret_ExpandEnvironmentStringsA)

    param_dict = {"src": src}
    _xrk_api_invoke_detail(dbg, "ExpandEnvironmentStringsA", param_dict)
    return param_dict


def handler_ret_ExpandEnvironmentStringsW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_ExpandEnvironmentStringsW
    assert v_tmp_addr_result_ExpandEnvironmentStringsW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_ExpandEnvironmentStringsW)
    _xrk_api_invoke_retn_detail(dbg, "ExpandEnvironmentStringsW", ret_dict={"ret_str": result_str})

    v_tmp_addr_result_ExpandEnvironmentStringsW = None
    dbg.bp_del(dbg.context.Eip)
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
    src = dbg.read_stack_p_unicode_string(4)
    result_addr = dbg.read_stack_int32(8)

    global v_tmp_addr_result_ExpandEnvironmentStringsW
    assert v_tmp_addr_result_ExpandEnvironmentStringsW is None
    v_tmp_addr_result_ExpandEnvironmentStringsW = result_addr

    # 00030645 - 000305E6 = 0x5F
    dbg.bp_set(dbg.context.Eip + 0x5F, handler=handler_ret_ExpandEnvironmentStringsW)

    param_dict = {"src": src}
    _xrk_api_invoke_detail(dbg, "ExpandEnvironmentStringsW", param_dict)
    return param_dict


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
    addr = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0xC)
    protect = dbg.read_stack_int32(0x10)
    protect_str = protect_value_to_str(protect)

    param_dict = {"addr": "%.8X" % addr, "size_protect": "%.8X" % size, "protect": protect_str}
    _xrk_api_invoke_detail(dbg, "VirtualProtectEx", param_dict)
    return param_dict


def handler_MiniDumpWriteDump(dbg):
    """
        parse params
    """
    pid = dbg.read_stack_int32(8)
    pid_str = _pid_to_procname(dbg, pid)

    param_dict = {"proc": pid_str}
    _xrk_api_invoke_detail(dbg, "MiniDumpWriteDump", param_dict)
    return param_dict


def handler_SetErrorMode(dbg):
    """
        parse param

        kernel32.SetErrorMode

        SetErrorMode-->NtSetInformationProcess

            _In_ UINT uMode
    """
    mode = dbg.read_stack_int32(4)

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

    param_dict = {"mode": mode_str}
    _xrk_api_invoke_detail(dbg, "SetErrorMode", param_dict)
    return param_dict


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
    pinfo = dbg.read_stack_int32(4)
    verb = dbg.read_p_unicode_string(pinfo + 0xC)
    file = dbg.read_p_unicode_string(pinfo + 0x10)
    parm = dbg.read_p_unicode_string(pinfo + 0x14)
    dir_ = dbg.read_p_unicode_string(pinfo + 0x18)

    _add_proc_to_proc_summary(file)

    param_dict = {"verb": verb, "file": file, "param": parm, "dir": dir_}
    _xrk_api_invoke_detail(dbg, "ShellExecuteExW", param_dict)
    return param_dict


def handler_SHGetFolderPathW(dbg):
    """
        parse params
    """
    csidl = dbg.read_stack_int32(8)

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

    param_dict = {"csidl": "%.8X-%s" % (csidl, csidl_str)}
    _xrk_api_invoke_detail(dbg, "SHGetFolderPathW", param_dict)
    return param_dict


def handler_ret_GetComputerNameW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetComputerNameW
    assert v_tmp_addr_result_GetComputerNameW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetComputerNameW)
    _xrk_api_invoke_retn_detail(dbg, "GetComputerNameW", ret_dict={"cmp_name": result_str})

    v_tmp_addr_result_GetComputerNameW = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetComputerNameW(dbg):
    """
        record result

        kernel32.GetComputerNameW

        GetComputerNameA-->GetComputerNameW-->NtOpenKey/NtCreateKey(ntdll)

          _Out_   LPTSTR  lpBuffer,
          _Inout_ LPDWORD lpnSize
    """
    global v_tmp_addr_result_GetComputerNameW
    assert v_tmp_addr_result_GetComputerNameW is None

    v_tmp_addr_result_GetComputerNameW = dbg.read_stack_int32(4)
    # 000317A3 - 000316B7 = 0xEC
    dbg.bp_set(dbg.context.Eip + 0xEC, handler=handler_ret_GetComputerNameW)

    _xrk_api_invoke_detail(dbg, "GetComputerNameW")
    return ""


def handler_ret_GetComputerNameExW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetComputerNameExW
    assert v_tmp_addr_result_GetComputerNameExW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetComputerNameExW)
    _xrk_api_invoke_retn_detail(dbg, "GetComputerNameExW", ret_dict={"cmp_name": result_str})

    v_tmp_addr_result_GetComputerNameExW = None
    dbg.bp_del(dbg.context.Eip)
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
    type_ = dbg.read_stack_int32(4)
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

    param_dict = "(type:%s)" % type_str

    # there are special occasions where "GetComputerNameExW" is invoked again before last "retn" triggered.
    global v_tmp_addr_result_GetComputerNameExW
    if v_tmp_addr_result_GetComputerNameExW is None:

        v_tmp_addr_result_GetComputerNameExW = dbg.read_stack_int32(8)
        # 0002026B - 000201D9 = 0x92
        dbg.bp_set(dbg.context.Eip + 0x92, handler=handler_ret_GetComputerNameExW)

        _xrk_api_invoke_detail(dbg, "GetComputerNameExW", param_dict)

    else:
        _xrk_api_invoke_detail(dbg, "GetComputerNameExW", param_dict, "invoked again before last retn triggered, so we're ignoring this result string")

    return param_dict


def handler_ret_GetCurrentDirectoryA(dbg):
    """
        modify result
    """
    global v_tmp_addr_result_GetCurrentDirectoryA
    assert v_tmp_addr_result_GetCurrentDirectoryA is not None

    result_str = dbg.read_ascii_string(v_tmp_addr_result_GetCurrentDirectoryA)

    global v_tmp_fake_module_file_name
    assert v_tmp_fake_module_file_name is not None
    dbg.write_ascii_string(v_tmp_addr_result_GetCurrentDirectoryA, v_tmp_fake_module_file_name)

    _xrk_api_invoke_retn_detail(dbg, "GetCurrentDirectoryA", ret_dict={"cur_dir": result_str}, extrainfo="force ret to: %s" % v_tmp_fake_module_file_name)

    v_tmp_addr_result_GetCurrentDirectoryA = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetCurrentDirectoryA(dbg):
    """
        might modify result
    """
    global v_tmp_fake_module_file_name
    if v_tmp_fake_module_file_name is not None:

        global v_tmp_addr_result_GetCurrentDirectoryA
        assert v_tmp_addr_result_GetCurrentDirectoryA is None

        v_tmp_addr_result_GetCurrentDirectoryA = dbg.read_stack_int32(8)
        # 000350A3 - 00035016 = 0x8D
        dbg.bp_set(dbg.context.Eip + 0x8D, handler=handler_ret_GetCurrentDirectoryA)

    _xrk_api_invoke_detail(dbg, "GetCurrentDirectoryA")
    return ""


def handler_ret_GetCurrentDirectoryW(dbg):
    """
        modify result
    """
    global v_tmp_addr_result_GetCurrentDirectoryW
    assert v_tmp_addr_result_GetCurrentDirectoryW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetCurrentDirectoryW)

    global v_tmp_fake_module_file_name
    assert v_tmp_fake_module_file_name is not None
    dbg.write_unicode_string(v_tmp_addr_result_GetCurrentDirectoryW, v_tmp_fake_module_file_name)

    _xrk_api_invoke_retn_detail(dbg, "GetCurrentDirectoryW", ret_dict={"cur_dir": result_str}, extrainfo="force ret to: %s" % v_tmp_fake_module_file_name)

    v_tmp_addr_result_GetCurrentDirectoryW = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetCurrentDirectoryW(dbg):
    """
        might modify result
    """
    global v_tmp_fake_module_file_name
    if v_tmp_fake_module_file_name is not None:

        global v_tmp_addr_result_GetCurrentDirectoryW
        assert v_tmp_addr_result_GetCurrentDirectoryW is None

        v_tmp_addr_result_GetCurrentDirectoryW = dbg.read_stack_int32(8)
        # 0000B91E - 0000B907 = 0x17
        dbg.bp_set(dbg.context.Eip + 0x17, handler=handler_ret_GetCurrentDirectoryW)

    _xrk_api_invoke_detail(dbg, "GetCurrentDirectoryW")
    return ""


def handler_ret_GetModuleFileNameW(dbg):
    """
        modify result
    """
    global v_tmp_addr_result_GetModuleFileNameW
    assert v_tmp_addr_result_GetModuleFileNameW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetModuleFileNameW)

    global v_tmp_fake_module_file_name
    if v_tmp_fake_module_file_name:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameW", ret_dict={"name": result_str}, extrainfo="force ret to: %s" % v_tmp_fake_module_file_name)
            dbg.write_unicode_string(v_tmp_addr_result_GetModuleFileNameW, v_tmp_fake_module_file_name)

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameW", ret_dict={"name": result_str}, extrainfo="intrude debugee not allowed, so we cancel it")

    v_tmp_addr_result_GetModuleFileNameW = None
    dbg.bp_del(dbg.context.Eip)

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
    h_md = dbg.read_stack_int32(4)
    global v_tmp_fake_module_file_name

    if h_md == 0 and v_tmp_fake_module_file_name is not None:

        global v_tmp_addr_result_GetModuleFileNameW
        assert v_tmp_addr_result_GetModuleFileNameW is None
        v_tmp_addr_result_GetModuleFileNameW = dbg.read_stack_int32(8)
        # 0000B4FE - 0000B465 = 0x99
        dbg.bp_set(dbg.context.Eip + 0x99, handler=handler_ret_GetModuleFileNameW)

    _xrk_api_invoke_detail(dbg, "GetModuleFileNameW")
    return ""


def handler_ret_GetModuleFileNameExW(dbg):
    """
        modify result
    """
    global v_tmp_addr_result_GetModuleFileNameExW
    assert v_tmp_addr_result_GetModuleFileNameExW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetModuleFileNameExW)

    global v_tmp_fake_module_file_name
    if v_tmp_fake_module_file_name:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameExW", ret_dict={"name": result_str}, extrainfo="force ret to: %s" % v_tmp_fake_module_file_name)
            dbg.write_unicode_string(v_tmp_addr_result_GetModuleFileNameExW, v_tmp_fake_module_file_name)

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetModuleFileNameExW", ret_dict={"name": result_str}, extrainfo="intrude debugee not allowed, so we cancel it")

    v_tmp_addr_result_GetModuleFileNameExW = None
    dbg.bp_del(dbg.context.Eip)

    return defines.DBG_CONTINUE


def handler_GetModuleFileNameExW(dbg):
    """
        might modify result
    """
    h_md = dbg.read_stack_int32(8)
    global v_tmp_fake_module_file_name

    if h_md == 0 and v_tmp_fake_module_file_name is not None:

        global v_tmp_addr_result_GetModuleFileNameExW
        assert v_tmp_addr_result_GetModuleFileNameExW is None
        v_tmp_addr_result_GetModuleFileNameExW = dbg.read_stack_int32(0xC)
        # 000017D3 - 0000176A = 0x69
        dbg.bp_set(dbg.context.Eip + 0x69, handler=handler_ret_GetModuleFileNameExW)

    _xrk_api_invoke_detail(dbg, "GetModuleFileNameExW")
    return ""


def handler_GetProcessImageFileNameA(dbg):
    """
        might modify result
    """
    # todo: we only modify result when querying current process
    _xrk_api_invoke_detail(dbg, "GetProcessImageFileNameA")
    return ""


def handler_GetProcessImageFileNameW(dbg):
    """
        might modify result
    """
    # todo: we only modify result when querying current process
    _xrk_api_invoke_detail(dbg, "GetProcessImageFileNameW")
    return ""


def handler_ret_GetVersion(dbg):
    """
        record result
    """
    _xrk_api_invoke_retn_detail(dbg, "GetVersion", ret_dict={"ver": "%d" % dbg.context.Eax})

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetVersion(dbg):
    """
        record result

        kernel32.GetVersion

          void
    """
    # 0001129A - 0001126A = 0x30
    dbg.bp_set(dbg.context.Eip + 0x30, handler=handler_ret_GetVersion)

    _xrk_api_invoke_detail(dbg, "GetVersion")
    return ""


def handler_ret_GetVersionExW(dbg):
    """
    """
    global v_tmp_addr_result_GetVersionExW
    assert v_tmp_addr_result_GetVersionExW is not None

    major_ver = dbg.read_int32(v_tmp_addr_result_GetVersionExW + 4)
    minor_ver = dbg.read_int32(v_tmp_addr_result_GetVersionExW + 8)
    build_num = dbg.read_int32(v_tmp_addr_result_GetVersionExW + 0xC)
    platform_id = dbg.read_int32(v_tmp_addr_result_GetVersionExW + 0x10)
    csd_ver = dbg.read_p_ascii_string(v_tmp_addr_result_GetVersionExW + 0x14)

    _xrk_api_invoke_retn_detail(dbg, "GetVersionExW", ret_dict={"ver": "%d:%d-%d-%d-%s" % (major_ver, minor_ver, build_num, platform_id, csd_ver)})

    v_tmp_addr_result_GetVersionExW = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetVersionExW(dbg):
    """
        record result

        kernel32.GetVersionExW

        GetVersionExA-->GetVersionExW

          _Inout_ LPOSVERSIONINFO lpVersionInfo
    """
    global v_tmp_addr_result_GetVersionExW
    assert v_tmp_addr_result_GetVersionExW is None

    v_tmp_addr_result_GetVersionExW = dbg.read_stack_int32(4)
    # 0000AF32 - 0000AEF5 = 0x3D
    dbg.bp_set(dbg.context.Eip + 0x3D, handler=handler_ret_GetVersionExW)

    _xrk_api_invoke_detail(dbg, "GetVersionExW")
    return ""


def handler_ret_GetCommandLineA(dbg):
    """
        record result
    """
    result_str = dbg.read_ascii_string(dbg.context.Eax)

    global v_tmp_fake_module_file_name
    if v_tmp_fake_module_file_name is not None:
        if result_str.count("\"") == 2:

            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineA", ret_dict={"cmd_line": result_str}, extrainfo="force retn to: %s" % v_tmp_fake_module_file_name)
            dbg.write_ascii_string(dbg.context.Eax, "\"" + v_tmp_fake_module_file_name + "\"")

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineA", ret_dict={"cmd_line": result_str})
            _pt_log(">>> not implemented")
            assert False

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetCommandLineA(dbg):
    """
        record result

        kernel32.GetCommandLineA

          void
    """
    # 00012FB2 - 00012FAD = 0x5
    dbg.bp_set(dbg.context.Eip + 0x05, handler=handler_ret_GetCommandLineA)

    _xrk_api_invoke_detail(dbg, "GetCommandLineA")
    return ""


def handler_ret_GetCommandLineW(dbg):
    """
        record result
    """
    result_str = dbg.read_unicode_string(dbg.context.Eax)

    global v_tmp_fake_module_file_name
    if v_tmp_fake_module_file_name is not None:
        if result_str.count("\"") == 2:

            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineW", ret_dict={"cmd_line": result_str}, extrainfo="force retn to: %s" % v_tmp_fake_module_file_name)
            dbg.write_unicode_string(dbg.context.Eax, "\"" + v_tmp_fake_module_file_name + "\"")

        else:
            _xrk_api_invoke_retn_detail(dbg, "GetCommandLineW", ret_dict={"cmd_line": result_str})
            _pt_log(">>> not implemented")
            assert False

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetCommandLineW(dbg):
    """
        record result

        kernel32.GetCommandLineW

          void
    """
    # 00017018 - 00017013 = 0x5
    dbg.bp_set(dbg.context.Eip + 0x05, handler=handler_ret_GetCommandLineW)

    _xrk_api_invoke_detail(dbg, "GetCommandLineW")
    return ""


def handler_ret_GetTempPathW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetTempPathW
    assert v_tmp_addr_result_GetTempPathW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetTempPathW)
    _xrk_api_invoke_retn_detail(dbg, "GetTempPathW", ret_dict={"ret_path": result_str})

    v_tmp_addr_result_GetTempPathW = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetTempPathW(dbg):
    """
        record result

        kernel32.GetTempPathW

        GetTempPathA-->GetTempPathW-->BasepGetTempPathW-->RtlQueryEnvironmentVariable_U

          _In_  DWORD  nBufferLength,
          _Out_ LPTSTR lpBuffer
    """
    global v_tmp_addr_result_GetTempPathW
    assert v_tmp_addr_result_GetTempPathW is None

    v_tmp_addr_result_GetTempPathW = dbg.read_stack_int32(8)
    # 0003078C - 00030779 = 0x13
    dbg.bp_set(dbg.context.Eip + 0x13, handler=handler_ret_GetTempPathW)

    _xrk_api_invoke_detail(dbg, "GetTempPathW")
    return ""


def handler_ret_GetTempFileNameW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetTempFileNameW
    assert v_tmp_addr_result_GetTempFileNameW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetTempFileNameW)
    _xrk_api_invoke_retn_detail(dbg, "GetTempFileNameW", ret_dict={"ret_name": result_str})

    v_tmp_addr_result_GetTempFileNameW = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetTempFileNameW(dbg):
    """
        record result
    """
    path = dbg.read_stack_p_unicode_string(4)
    prefix = dbg.read_stack_p_unicode_string(8)
    result_addr = dbg.read_stack_int32(0x10)

    global v_tmp_addr_result_GetTempFileNameW
    assert v_tmp_addr_result_GetTempFileNameW is None
    v_tmp_addr_result_GetTempFileNameW = result_addr
    # 00035BAE - 000359CF = 0x1DF
    dbg.bp_set(dbg.context.Eip + 0x1DF, handler=handler_ret_GetTempFileNameW)

    param_dict = {"path": path, "prefix": prefix}
    _xrk_api_invoke_detail(dbg, "GetTempFileNameW", param_dict)
    return param_dict


def handler_ret_GetSystemDirectoryA(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetSystemDirectoryA
    assert v_tmp_addr_result_GetSystemDirectoryA is not None

    result_str = dbg.read_ascii_string(v_tmp_addr_result_GetSystemDirectoryA)
    _xrk_api_invoke_retn_detail(dbg, "GetSystemDirectoryA", ret_dict={"sys_dir": result_str})

    v_tmp_addr_result_GetSystemDirectoryA = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetSystemDirectoryA(dbg):
    """
        record result

        kernel32.GetSystemDirectoryA

        GetSystemDirectoryA-->BaseWindowsSystemDirectory/RtlUnicodeToMultiByteSize/xx

          _Out_ LPTSTR lpBuffer,
          _In_  UINT   uSize
    """
    global v_tmp_addr_result_GetSystemDirectoryA
    assert v_tmp_addr_result_GetSystemDirectoryA is None

    # # for now, we don't need to modify result.
    # v_tmp_addr_result_GetSystemDirectoryA = dbg.read_stack_int32(4)
    # # 00014FD8 - 00014F7A = 0x5E
    # dbg.bp_set(dbg.context.Eip + 0x5E, handler=handler_ret_GetSystemDirectoryA)

    _xrk_api_invoke_detail(dbg, "GetSystemDirectoryA")
    return ""


def handler_ret_GetSystemDirectoryW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetSystemDirectoryW
    assert v_tmp_addr_result_GetSystemDirectoryW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetSystemDirectoryW)
    _xrk_api_invoke_retn_detail(dbg, "GetSystemDirectoryW", ret_dict={"sys_dir": result_str})

    v_tmp_addr_result_GetSystemDirectoryW = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetSystemDirectoryW(dbg):
    """
        record result

        kernel32.GetSystemDirectoryW

        GetSystemDirectoryW-->BaseWindowsSystemDirectory

          _Out_ LPTSTR lpBuffer,
          _In_  UINT   uSize
    """
    global v_tmp_addr_result_GetSystemDirectoryW
    assert v_tmp_addr_result_GetSystemDirectoryW is None

    # # for now, we don't need to modify result.
    # v_tmp_addr_result_GetSystemDirectoryW = dbg.read_stack_int32(4)
    # # 00031E24 - 00031DD3 = 0x51
    # dbg.bp_set(dbg.context.Eip + 0x51, handler=handler_ret_GetSystemDirectoryW)

    _xrk_api_invoke_detail(dbg, "GetSystemDirectoryW")
    return ""


def handler_ret_GetPrivateProfileStringA(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetPrivateProfileStringA
    assert v_tmp_addr_result_GetPrivateProfileStringA is not None

    result_str = dbg.read_ascii_string(v_tmp_addr_result_GetPrivateProfileStringA)
    _xrk_api_invoke_retn_detail(dbg, "GetPrivateProfileStringA", ret_dict={"ret_str": result_str})

    v_tmp_addr_result_GetPrivateProfileStringA = None
    dbg.bp_del(dbg.context.Eip)
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
    app_name = dbg.read_stack_p_ascii_string(4)
    key_name = dbg.read_stack_p_ascii_string(8)
    default = dbg.read_stack_p_ascii_string(0xC)
    file = dbg.read_stack_p_ascii_string(0x18)

    global v_tmp_addr_result_GetPrivateProfileStringA
    assert v_tmp_addr_result_GetPrivateProfileStringA is None
    v_tmp_addr_result_GetPrivateProfileStringA = dbg.read_stack_int32(0x10)
    # 00032BC0 - 00032B6E = 0x52
    dbg.bp_set(dbg.context.Eip + 0x52, handler=handler_ret_GetPrivateProfileStringA)

    param_dict = {"app": app_name, "key": key_name, "default": default, "file": file}
    _xrk_api_invoke_detail(dbg, "GetPrivateProfileStringA", param_dict)
    return param_dict


def handler_ret_GetPrivateProfileStringW(dbg):
    """
        record result
    """
    global v_tmp_addr_result_GetPrivateProfileStringW
    assert v_tmp_addr_result_GetPrivateProfileStringW is not None

    result_str = dbg.read_unicode_string(v_tmp_addr_result_GetPrivateProfileStringW)
    _xrk_api_invoke_retn_detail(dbg, "GetPrivateProfileStringW", ret_dict={"ret_str": result_str})

    v_tmp_addr_result_GetPrivateProfileStringW = None
    dbg.bp_del(dbg.context.Eip)
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
    app_name = dbg.read_stack_p_unicode_string(4)
    key_name = dbg.read_stack_p_unicode_string(8)
    default = dbg.read_stack_p_unicode_string(0xC)
    file = dbg.read_stack_p_unicode_string(0x18)

    global v_tmp_addr_result_GetPrivateProfileStringW
    assert v_tmp_addr_result_GetPrivateProfileStringW is None
    v_tmp_addr_result_GetPrivateProfileStringW = dbg.read_stack_int32(0x10)
    # 0000FA61 - 0000F9ED = 0x74
    dbg.bp_set(dbg.context.Eip + 0x74, handler=handler_ret_GetPrivateProfileStringW)

    param_dict = {"app": app_name, "key": key_name, "default": default, "file": file}
    _xrk_api_invoke_detail(dbg, "GetPrivateProfileStringW", param_dict)
    return param_dict


def handler_ret_GetTickCount(dbg):
    """
        modify result
    """
    cur_ret = dbg.context.Eax

    global v_tmp_fake_tick_gap
    if v_tmp_fake_tick_gap == 0:

        # first time we modify result of GetTickCount, and we calc gap here

        global v_tmp_fake_tick_start
        assert v_tmp_fake_tick_start is not None

        new_ret = v_tmp_fake_tick_start
        v_tmp_fake_tick_gap = v_tmp_fake_tick_start - cur_ret

    else:
        # we do this, because we specified "fake_tick_start" or SleepEx is called.
        new_ret = cur_ret + v_tmp_fake_tick_gap

    global v_tmp_is_intrude_debugee
    if v_tmp_is_intrude_debugee:

        _xrk_api_invoke_retn_detail(dbg, "GetTickCount", extrainfo="force ret from %d to %d, gap: %d" % (cur_ret, new_ret, v_tmp_fake_tick_gap))
        dbg.set_register("EAX", new_ret)

    else:
        _xrk_api_invoke_retn_detail(dbg, "GetTickCount", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetTickCount(dbg):
    """
        might mofify result

        kerner32.GetTickCount

          void
    """
    global v_tmp_fake_tick_gap
    if v_tmp_fake_tick_gap is None:
        v_tmp_fake_tick_gap = 0

    global v_tmp_fake_tick_start
    if v_tmp_fake_tick_start is not None or v_tmp_fake_tick_gap != 0:

        # 0000933C - 0000932E = 0xE
        dbg.bp_set(dbg.context.Eip + 0xE, handler=handler_ret_GetTickCount)

    _xrk_api_invoke_detail(dbg, "GetTickCount")
    return ""


def systime_str(time_):
    """
        @param: time_ : obj : defines.SYSTEMTIME()

        @return: string :

        ('wYear',           WORD),
        ('wMonth',          WORD),
        ('wDayOfWeek',      WORD),
        ('wDay',            WORD),
        ('wHour',           WORD),
        ('wMinute',         WORD),
        ('wSecond',         WORD),
        ('wMilliseconds',   WORD),
    """
    return "%.4dY%.2dM%.2dD%.2dH%.2dM%.2dS%.3d" % (time_.wYear, time_.wMonth, time_.wDay, time_.wHour, time_.wMinute, time_.wSecond, time_.wMilliseconds)


def parse_systime(dbg, p_time):
    """
        @param: p_time : int : pointer ot defines.SYSTEMTIME()

        @return: defines.SYSTEMTIME()
    """
    ret = defines.SYSTEMTIME()
    ret.wYear = dbg.read_int16(p_time)
    ret.wMonth = dbg.read_int16(p_time + 2)
    ret.wDay = dbg.read_int16(p_time + 6)
    ret.wHour = dbg.read_int16(p_time + 8)
    ret.wMinute = dbg.read_int16(p_time + 10)
    ret.wSecond = dbg.read_int16(p_time + 12)
    ret.wMilliseconds = dbg.read_int16(p_time + 14)
    return ret


def dbg_write_systime(dbg, p_time, new_time):
    """
        @param: p_time   : int : pointer
        @param: new_time : obj : defines.SYSTEMTIME()
    """
    dbg.write_int16(p_time, new_time.wYear)
    dbg.write_int16(p_time + 2, new_time.wMonth)
    dbg.write_int16(p_time + 6, new_time.wDay)
    dbg.write_int16(p_time + 8, new_time.wHour)
    dbg.write_int16(p_time + 10, new_time.wMinute)
    dbg.write_int16(p_time + 12, new_time.wSecond)
    dbg.write_int16(p_time + 14, new_time.wMilliseconds)


MSECS_SEC = 1000
MSECS_MINUTE = MSECS_SEC * 60
MSECS_HOUR = MSECS_MINUTE * 60
MSECS_DAY = MSECS_HOUR * 24
MSECS_MONTH = MSECS_DAY * 30
MSECS_YEAR = MSECS_MONTH * 365


def calc_systime_gap(time1, time2):
    """
        @param: time1 : obj : defines.SYSTEMTIME()
        @param: time2 : obj : defines.SYSTEMTIME()

        @return: int : msecs
    """
    gap_year = time1.wYear = time2.wYear
    gap_month = time1.wMonth = time2.wMonth
    gap_day = time1.wDay = time2.wDay
    gap_hour = time1.wHour = time2.wHour
    gap_minute = time1.wMinute = time2.wMinute
    gap_secs = time1.wSecond = time2.wSecond
    gap_msecs = time1.wMilliseconds = time2.wMilliseconds

    return gap_year * MSECS_YEAR + gap_month * MSECS_MONTH + gap_day * MSECS_DAY + gap_hour * MSECS_HOUR + gap_minute * MSECS_MINUTE + gap_secs * MSECS_SEC + gap_msecs


def add_systime_gap(time_, gap):
    """
        @param: time_ : obj : defines.SYSTEMTIME()
        @param: gap   : int : msecs gap

        @return: obj : defines.SYSTEMTIME()
    """
    # time_gap = gap_to_systime(gap)
    ret = defines.SYSTEMTIME()

    # is_add_1_to_secs = False
    # if time_.wMilliseconds + time_gap.wMilliseconds > 1000:
    #     pass
    # else:
    #     pass
    # ret.wYear = time_.wYear + time_gap.wYear
    # ret.wMonth = time_.wMonth + time_gap.wMonth
    # ret.wDay = time_.wDay + time_gap.wDay
    # ret.wHour = time_.wHour + time_gap.wHour
    # ret.wMinute = time_.wMinute + time_gap.wMinute
    # ret.wSecond = time_.wSecond + time_gap.wSecond
    # ret.wMilliseconds = dbg.read_int16(p_time + 14)
    return ret


def handler_ret_GetSystemTime(dbg):
    """
        modify result
    """
    global v_tmp_addr_result_GetSystemTime
    assert v_tmp_addr_result_GetSystemTime is not None

    cur_sys_time = parse_systime(dbg, v_tmp_addr_result_GetSystemTime)

    global v_tmp_fake_systime_gap
    if v_tmp_fake_systime_gap == 0:

        # the first time call GetSystemTime() and we specified "fake_systime_start"
        global v_tmp_fake_systime_start
        assert v_tmp_fake_systime_start is not None

        new_time = v_tmp_fake_systime_start
        v_tmp_fake_systime_gap = calc_systime_gap(v_tmp_fake_systime_start, cur_sys_time)

    else:
        # we specified "fake_system_start" or SleepEx has already been invoked
        new_time = add_systime_gap(cur_sys_time, v_tmp_fake_systime_gap)

    _xrk_api_invoke_retn_detail(dbg, "GetSystemTime", ret_dict={"sys_time": systime_str(cur_sys_time)}, extrainfo="modify to: %s" % systime_str(new_time))

    dbg_write_systime(dbg, v_tmp_addr_result_GetSystemTime, new_time)

    v_tmp_addr_result_GetSystemTime = None
    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_GetSystemTime(dbg):
    """
        might modify result

        kernel32.GetSystemTime

        GetSystemTime-->??/RtlTimeToTimeFields

          LPSYSTEMTIME lpSystemTime
    """
    global v_tmp_fake_systime_gap
    if v_tmp_fake_systime_gap is None:
        v_tmp_fake_systime_gap = 0

    global v_tmp_fake_systime_start
    if v_tmp_fake_systime_start is not None or v_tmp_fake_systime_gap != 0:

        global v_tmp_addr_result_GetSystemTime
        assert v_tmp_addr_result_GetSystemTime is None
        v_tmp_addr_result_GetSystemTime = dbg.read_stack_int32(4)
        # 000017E1 - 0000176F = 0x72
        dbg.bp_set(dbg.context.Eip + 0x72, handler=handler_ret_GetSystemTime)

    _xrk_api_invoke_detail(dbg, "GetSystemTime")
    return ""


def handler_GetModuleHandleW(dbg):
    """
        parse params

        kernel32.GetModuleHandleW

        GetModuleHandleA-->GetModuleHandleW-->BasepGetModuleHandleExW

          _In_opt_ LPCTSTR lpModuleName
    """
    file_v = dbg.read_stack_int32(4)
    if file_v == 0:

        file_str = "[Debugee]"

        param_dict = {"file": file_str}
        _xrk_api_invoke_detail(dbg, "GetModuleHandleW", param_dict, "retrieving mm pointer to debugee")

    else:
        file_str = dbg.read_stack_p_ascii_string(4)

        param_dict = {"file": file_str}
        _xrk_api_invoke_detail(dbg, "GetModuleHandleW", param_dict)

    return param_dict


def handler_GetModuleHandleExW(dbg):
    """
        parse params

        kernel32.GetModuleHandleExW

        GetModuleHandleExA-->GetModuleHandleExW-->BasepGetModuleHandleExW

          _In_     DWORD   dwFlags,
          _In_opt_ LPCTSTR lpModuleName,
          _Out_    HMODULE *phModule
    """
    file_v = dbg.read_stack_int32(8)
    if file_v == 0:

        file_str = "[Debugee]"

        param_dict = {"file": file_str}
        _xrk_api_invoke_detail(dbg, "GetModuleHandleExW", param_dict, "retrieving mm pointer to debugee")

    else:
        file_str = dbg.read_stack_p_ascii_string(8)

        param_dict = {"file": file_str}
        _xrk_api_invoke_detail(dbg, "GetModuleHandleExW", param_dict)

    return param_dict


def handler_WaitForSingleObjectEx(dbg):
    """
        ignore wait, step forward and change ret result

        kernel32.WaitForSingleObjectEx

        WaitForSingleObject-->WaitForSingleObjectEx-->NtWaitForSingleObject

          HANDLE hHandle,
          DWORD dwMilliseconds
          BOOL bAlertable
    """
    global v_tmp_is_ignore_all_wait_obj
    if v_tmp_is_ignore_all_wait_obj:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            # 000095A4 - 000095BC = -0x18
            dbg.set_register("EIP", dbg.context.Eip - 0x18)
            dbg.set_register("EAX", 0)

            _xrk_api_invoke_detail(dbg, "WaitForSingleObjectEx", None, extrainfo="brute force to retn!")
            return ""

        else:
            _xrk_api_invoke_detail(dbg, "WaitForSingleObjectEx", None, extrainfo="intrude debugee not allowed, so we cancel it")

    else:
        _xrk_api_invoke_detail(dbg, "WaitForSingleObjectEx")
        return ""


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
    cnt = dbg.read_stack_int32(4)
    param_dict = {"cnt": "%d" % cnt}

    global v_tmp_is_ignore_all_wait_obj
    if v_tmp_is_ignore_all_wait_obj:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            # 0x00002600 - 00002550 = 0xB0
            dbg.set_register("EIP", dbg.context.Eip + 0xB0)
            dbg.set_register("EAX", 0)

            _xrk_api_invoke_detail(dbg, "WaitForMultipleObjectsEx", param_dict, extrainfo="brute force to retn!")

        else:
            _xrk_api_invoke_detail(dbg, "WaitForMultipleObjectsEx", param_dict, extrainfo="intrude debugee not allowed, so we cancel it")

    else:
        _xrk_api_invoke_detail(dbg, "WaitForMultipleObjectsEx", param_dict)

    return param_dict


def handler_SetTimer(dbg):
    """
        nothing special....

        user32.SetTimer

          _In_opt_ HWND      hWnd,
          _In_     UINT_PTR  nIDEvent,
          _In_     UINT      uElapse,
          _In_opt_ TIMERPROC lpTimerFunc
    """
    evt_id = dbg.read_stack_int32(8)
    elaspe = dbg.read_stack_int32(0xC)
    cbk = dbg.read_stack_int32(0x10)

    param_dict = {"evt_id": evt_id, "elaspe": elaspe, "cbk": "%.8X" % cbk}
    _xrk_api_invoke_detail(dbg, "SetTimer", param_dict)
    return param_dict


def handler_KillTimer(dbg):
    """
        nothing special....

        user32.KillTimer

          _In_opt_  HWND hWnd,
          _In_      UINT_PTR uIDEvent
    """
    evt_id = dbg.read_stack_int32(8)

    param_dict = {"evt_id": "%d" % evt_id}
    _xrk_api_invoke_detail(dbg, "KillTimer", param_dict)
    return param_dict


def hanler_ret_wnsprintfA(dbg):
    """
        record format ret
    """
    global v_tmp_addr_result_formatA
    assert v_tmp_addr_result_formatA is not None

    ret_str = dbg.read_ascii_string(v_tmp_addr_result_formatA)
    _xrk_api_invoke_retn_detail(dbg, "wnsprintfA", ret_dict={"ret_str": ret_str})

    v_tmp_addr_result_formatA = None
    dbg.bp_del(dbg.context.Eip)

    return defines.DBG_CONTINUE


def handler_wnsprintfA(dbg):
    """
        might record format ret

        shlwapi.wnsprintfA

        wnsprintfA-->wvnsprintfA

          _Out_ PTSTR  pszDest,
          _In_  int    cchDest,
          _In_  PCTSTR pszFmt,
          _In_         ...
    """
    global v_tmp_addr_result_formatA
    assert v_tmp_addr_result_formatA is None
    v_tmp_addr_result_formatA = dbg.read_stack_int32(0)

    # 00008294 - 0000827C = 0x18
    dbg.bp_set(dbg.context.Eip + 0x18, handler=hanler_ret_wnsprintfA)

    # do not leave it to hanler_ret_wnsprintfA, we need this summary
    _xrk_api_invoke_detail(dbg, "wnsprintfA")
    return ""


def hanler_ret_wnsprintfW(dbg):
    """
        record format ret
    """
    global v_tmp_addr_result_formatW
    assert v_tmp_addr_result_formatW is not None

    ret_str = dbg.read_unicode_string(v_tmp_addr_result_formatW)
    _xrk_api_invoke_retn_detail(dbg, "wnsprintfW", ret_dict={"ret_str": ret_str})

    v_tmp_addr_result_formatW = None
    dbg.bp_del(dbg.context.Eip)

    return defines.DBG_CONTINUE


def handler_wnsprintfW(dbg):
    """
        might record format ret

        shlwapi.wnsprintfW

        wnsprintfW-->wvnsprintfW

          _Out_ PTSTR  pszDest,
          _In_  int    cchDest,
          _In_  PCTSTR pszFmt,
          _In_         ...
    """
    global v_tmp_addr_result_formatW
    assert v_tmp_addr_result_formatW is None
    v_tmp_addr_result_formatW = dbg.read_stack_int32(0)

    # 000093FE - 000093E6 = 0x18
    dbg.bp_set(dbg.context.Eip + 0x18, handler=hanler_ret_wnsprintfW)

    # do not leave it to hanler_ret_wnsprintfW, we need summary
    _xrk_api_invoke_detail(dbg, "wnsprintfW")
    return ""


def handler_ret_lstrcmpA(dbg):
    """
        modify result
    """
    if dbg.context.Eax != 0:

        _xrk_api_invoke_retn_detail(dbg, "lstrcmpA", extrainfo="modify result from %d to 0" % dbg.context.Eax)
        dbg.set_register("EAX", 0)

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_lstrcmpA(dbg):
    """
        may change result

        kernel32.lstrcmpA

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    str1 = dbg.read_stack_p_ascii_string(4)
    str2 = dbg.read_stack_p_ascii_string(8)

    extrainfo = None
    global v_tmp_equal_cmp_strings
    if v_tmp_equal_cmp_strings is not None and len(v_tmp_equal_cmp_strings) != 0:
        for str_x in v_tmp_equal_cmp_strings:
            if (str1 == str_x[0] and str2 == str_x[1]) or (str1 == str_x[1] and str2 == str_x[0]):
                # 00030D98 - 00030D64 = 0x34
                dbg.bp_set(dbg.context.Eip + 0x34, handler=handler_ret_lstrcmpA)
                extrainfo = "comparing some strings, will guarantee success"
                break

    param_dict = {"str1": str1, "str2": str2}
    _xrk_api_invoke_detail(dbg, "lstrcmpA", param_dict, extrainfo)
    return param_dict


def handler_ret_lstrcmpW(dbg):
    """
        modify result
    """
    if dbg.context.Eax != 0:
        _xrk_api_invoke_retn_detail(dbg, "lstrcmpW", extrainfo="modify result from %d to 0" % dbg.context.Eax)
        dbg.set_register("EAX", 0)

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_lstrcmpW(dbg):
    """
        may change result

        kernel32.lstrcmpW

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    str1 = dbg.read_stack_p_unicode_string(4)
    str2 = dbg.read_stack_p_unicode_string(8)

    global v_tmp_equal_cmp_strings
    if v_tmp_equal_cmp_strings is not None and len(v_tmp_equal_cmp_strings) != 0:
        for str_x in v_tmp_equal_cmp_strings:
            if (str1 == str_x[0] and str2 == str_x[1]) or (str1 == str_x[1] and str2 == str_x[0]):
                # 0000AA8A - 0000AA5C = 0x2E
                dbg.bp_set(dbg.context.Eip + 0x2E, handler=handler_ret_lstrcmpW)

    param_dict = {"str1": str1, "str2": str2}
    _xrk_api_invoke_detail(dbg, "lstrcmpW", param_dict)
    return param_dict


def handler_ret_lstrcmpiA(dbg):
    """
        modify result
    """
    if dbg.context.Eax != 0:
        _xrk_api_invoke_retn_detail(dbg, "lstrcmpiA", extrainfo="modify result from %d to 0" % dbg.context.Eax)
        dbg.set_register("EAX", 0)

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_lstrcmpiA(dbg):
    """
        may change result

        kernel32.lstrcmpiA

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    str1 = dbg.read_stack_p_ascii_string(4)
    str2 = dbg.read_stack_p_ascii_string(8)

    global v_tmp_equal_cmp_strings
    if v_tmp_equal_cmp_strings is not None and len(v_tmp_equal_cmp_strings) != 0:
        for str_x in v_tmp_equal_cmp_strings:
            if (str1 == str_x[0] and str2 == str_x[1]) or (str1 == str_x[1] and str2 == str_x[0]):
                # 0000BB62 - 0000BB31 = 0x31
                dbg.bp_set(dbg.context.Eip + 0x31, handler=handler_ret_lstrcmpiA)

    param_dict = {"str1": str1, "str2": str2}
    _xrk_api_invoke_detail(dbg, "lstrcmpiA", param_dict)
    return param_dict


def handler_ret_lstrcmpiW(dbg):
    """
        modify result
    """
    if dbg.context.Eax != 0:
        _xrk_api_invoke_retn_detail(dbg, "lstrcmpiW", extrainfo="modify result from %d to 0" % dbg.context.Eax)
        dbg.set_register("EAX", 0)

    dbg.bp_del(dbg.context.Eip)
    return defines.DBG_CONTINUE


def handler_lstrcmpiW(dbg):
    """
        may change result

        kernel32.lstrcmpiW

        _In_ LPCTSTR lpString1,
        _In_ LPCTSTR lpString2
    """
    str1 = dbg.read_stack_p_unicode_string(4)
    str2 = dbg.read_stack_p_unicode_string(8)

    global v_tmp_equal_cmp_strings
    if v_tmp_equal_cmp_strings is not None and len(v_tmp_equal_cmp_strings) != 0:
        for str_x in v_tmp_equal_cmp_strings:
            if (str1 == str_x[0] and str2 == str_x[1]) or (str1 == str_x[1] and str2 == str_x[0]):
                # 0000AA54 - 0000AA26 = 0x2E
                dbg.bp_set(dbg.context.Eip + 0x2E, handler=handler_ret_lstrcmpiW)

    param_dict = {"str1": str1, "str2": str2}
    _xrk_api_invoke_detail(dbg, "lstrcmpiW", param_dict)
    return param_dict


def handler_retn_VirtualAllocEx(dbg):
    """
        record alloc result
    """
    addr = dbg.context.Eax

    _xrk_api_invoke_retn_detail(dbg, "VirtualAllocEx", ret_dict={"ret_addr": "%.8X" % addr})

    global v_tmp_is_bpmmwrite_alloc_retn
    if v_tmp_is_bpmmwrite_alloc_retn:
        # todo
        # we only set first 2 bytes, check if is PE header
        pass

    # this is one shot
    dbg.bp_del(dbg.context.Eip)

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
    addr = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0xC)
    h_proc = dbg.read_stack_int32(4)
    h_proc_str = h_proc_to_proc_str(dbg, h_proc)
    protect = dbg.read_stack_int32(0x14)
    protect_str = protect_value_to_str(protect)

    global v_tmp_is_record_alloc_retn
    if v_tmp_is_record_alloc_retn:
        # 00009B49 - 00009B02 = 0x47
        dbg.bp_set(dbg.context.Eip + 0x47, handler=handler_retn_VirtualAllocEx)

    param_dict = {"proc": h_proc_str, "size_alloc": "%.8X" % size, "protect": protect_str}
    if addr != 0:
        param_dict["addr"] = "%.8X" % addr

    _xrk_api_invoke_detail(dbg, "VirtualAllocEx", param_dict)
    return param_dict


def handler_retn_RtlAllocateHeap(dbg):
    """
        record alloc result
    """
    addr = dbg.context.Eax

    _xrk_api_invoke_retn_detail(dbg, "RtlAllocateHeap", ret_dict={"ret_addr": "%.8X" % addr})

    global v_tmp_is_bpmmwrite_alloc_retn
    if v_tmp_is_bpmmwrite_alloc_retn:
        # todo
        # we only set first 2 bytes, check if is PE header
        pass

    # this is one shot
    dbg.bp_del(dbg.context.Eip)

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
    flags = dbg.read_stack_int32(8)
    size = dbg.read_stack_int32(0xC)

    global v_tmp_is_record_alloc_retn
    if v_tmp_is_record_alloc_retn:
        # 000101BB - 000100A4 = 0x117
        dbg.bp_set(dbg.context.Eip + 0x117, handler=handler_retn_RtlAllocateHeap)

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

    param_dict = {"size_alloc": "%.8X" % size, "flags": flags_str}
    _xrk_api_invoke_detail(dbg, "RtlAllocateHeap", param_dict)
    return param_dict


def handler_retn_RtlReAllocateHeap(dbg):
    """
        record alloc result
    """
    addr = dbg.context.Eax

    _xrk_api_invoke_retn_detail(dbg, "RtlReAllocateHeap", ret_dict={"ret_addr": "%.8X" % addr})

    global v_tmp_is_bpmmwrite_alloc_retn
    if v_tmp_is_bpmmwrite_alloc_retn:
        # todo
        # we only set first 2 bytes, check if is PE header
        pass

    # this is one shot
    dbg.bp_del(dbg.context.Eip)

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
    flags = dbg.read_stack_int32(8)
    ptr = dbg.read_stack_int32(0xC)
    size = dbg.read_stack_int32(0x10)

    global v_tmp_is_record_alloc_retn
    if v_tmp_is_record_alloc_retn:
        # 00019D8A - 00019B80 = 0x20A
        dbg.bp_set(dbg.context.Eip + 0x20A, handler=handler_retn_RtlReAllocateHeap)

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

    param_dict = {"size_alloc": "%.8X" % size, "flags": flags_str, "ptr": "%.8X" % ptr}
    _xrk_api_invoke_detail(dbg, "RtlReAllocateHeap", param_dict)
    return param_dict


def parse_msgbox_params(dbg, p_params):
    """
        typedef struct {
          UINT           cbSize;
          HWND           hwndOwner;
          HINSTANCE      hInstance;
          LPCTSTR        lpszText;
          LPCTSTR        lpszCaption;
          DWORD          dwStyle;
          LPCTSTR        lpszIcon;
          DWORD_PTR      dwContextHelpId;
          MSGBOXCALLBACK lpfnMsgBoxCallback;
          DWORD          dwLanguageId;
        } MSGBOXPARAMS, *PMSGBOXPARAMS;

        dwStyle:
            MB_ABORTRETRYIGNORE     0x00000002L
            MB_CANCELTRYCONTINUE    0x00000006L
            MB_HELP                 0x00004000L
            MB_OK                   0x00000000L
            MB_OKCANCEL             0x00000001L
            MB_RETRYCANCEL          0x00000005L
            MB_YESNO                0x00000004L
            MB_YESNOCANCEL          0x00000003L

        @return: TUPLE: (txt, caption, style_str, fn_cbk)
    """
    txt = dbg.read_p_ascii_string(p_params + 0xC)
    caption = dbg.read_p_ascii_string(p_params + 0x10)
    style = dbg.read_int32(p_params + 0x14)
    fn_cbk = dbg.read_int32(p_params + 0x20)

    style_str = ""
    if style & 0x00000002:
        style_str = "MB_ABORTRETRYIGNORE"
    if style & 0x00000006:
        style_str = style_str + "|MB_CANCELTRYCONTINUE"
    if style & 0x00004000:
        style_str = style_str + "|MB_HELP"
    if style & 0x00000000:
        style_str = style_str + "|MB_OK"
    if style & 0x00000001:
        style_str = style_str + "|MB_OKCANCEL"
    if style & 0x00000005:
        style_str = style_str + "|MB_RETRYCANCEL"
    if style & 0x00000004:
        style_str = style_str + "|MB_YESNO"
    if style & 0x00000003:
        style_str = style_str + "|MB_YESNOCANCEL"

    style_str = style_str.strip("|")

    return (txt, caption, style_str, fn_cbk)


def handler_MessageBoxIndirectA(dbg):
    """
        parse msgbox info

        user32.MessageBoxIndirectA

        MessageBoxIndirectA-->MessageBoxWorker

          _In_ const LPMSGBOXPARAMS lpMsgBoxParams
    """
    p_params = dbg.read_stack_int32(4)
    txt, caption, style_str, fn_cbk = parse_msgbox_params(dbg, p_params)

    param_dict = {"txt": txt, "caption": caption, "style": style_str, "cbk": "%.8X" % fn_cbk}
    _xrk_api_invoke_detail(dbg, "MessageBoxIndirectA", param_dict)
    return param_dict


def handler_MessageBoxIndirectW(dbg):
    """
        parse msgbox info

        user32.MessageBoxIndirectW

        MessageBoxIndirectW-->MessageBoxWorker

          _In_ const LPMSGBOXPARAMS lpMsgBoxParams
    """
    p_params = dbg.read_stack_int32(4)
    txt, caption, style_str, fn_cbk = parse_msgbox_params(dbg, p_params)

    param_dict = {"txt": txt, "caption": caption, "style": style_str, "cbk": "%.8X" % fn_cbk}
    _xrk_api_invoke_detail(dbg, "MessageBoxIndirectW", param_dict)
    return param_dict


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
    fn_cbk = dbg.read_int32(p_class + 0x4)
    menu_name = dbg.read_p_ascii_string(p_class + 0x20)
    class_name = dbg.read_p_ascii_string(p_class + 0x24)

    return (fn_cbk, menu_name, class_name)


def handler_RegisterClassA(dbg):
    """
        parse class info

        user32.RegisterClassA

        RegisterClassA-->RegisterClassExWOWA-->NtUserRegisterClassExWOW

          _In_ const WNDCLASS *lpWndClass
    """
    p_class = dbg.read_stack_int32(4)
    fn_cbk, menu_name, class_name = parse_winclass_params(dbg, p_class)

    param_dict = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    _xrk_api_invoke_detail(dbg, "RegisterClassA", param_dict)
    return param_dict


def handler_RegisterClassW(dbg):
    """
        parse class info

        user32.RegisterClassW

        RegisterClassW-->RegisterClassExWOWW-->NtUserRegisterClassExWOW

          _In_ const WNDCLASS *lpWndClass
    """
    p_class = dbg.read_stack_int32(4)
    fn_cbk, menu_name, class_name = parse_winclass_params(dbg, p_class)

    param_dict = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    _xrk_api_invoke_detail(dbg, "RegisterClassW", param_dict)
    return param_dict


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
    fn_cbk = dbg.read_int32(p_class + 0x8)
    menu_name = dbg.read_p_ascii_string(p_class + 0x24)
    class_name = dbg.read_p_ascii_string(p_class + 0x28)

    return (fn_cbk, menu_name, class_name)


def handler_RegisterClassExA(dbg):
    """
        parse class info

        user32.RegisterClassExA

        RegisterClassExA-->RegisterClassExWOWA=>>||

          _In_ const WNDCLASSEX *lpwcx
    """
    p_class = dbg.read_stack_int32(4)
    fn_cbk, menu_name, class_name = parse_winclassex_params(dbg, p_class)

    param_dict = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    _xrk_api_invoke_detail(dbg, "RegisterClassExA", param_dict)
    return param_dict


def handler_RegisterClassExW(dbg):
    """
        parse class info

        user32.RegisterClassExW

        RegisterClassExW-->RegisterClassExWOWW==>>||

          _In_ const WNDCLASSEX *lpwcx
    """
    p_class = dbg.read_stack_int32(4)
    fn_cbk, menu_name, class_name = parse_winclassex_params(dbg, p_class)

    param_dict = {"cbk": fn_cbk, "menu": menu_name, "class": class_name}
    _xrk_api_invoke_detail(dbg, "RegisterClassExW", param_dict)
    return param_dict


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
    code = dbg.read_stack_int32(8)

    param_dict = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    _xrk_api_invoke_detail(dbg, "PostMessageA", param_dict)
    return param_dict


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
    code = dbg.read_stack_int32(8)

    param_dict = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    _xrk_api_invoke_detail(dbg, "PostMessageW", param_dict)
    return param_dict


def parse_msg_params(dbg, p_msg):
    """
        typedef struct tagMSG {
          HWND   hwnd;
          UINT   message;
          WPARAM wParam;
          LPARAM lParam;
          DWORD  time;
          POINT  pt;
        } MSG, *PMSG, *LPMSG;

        @return: msg
    """
    msg = dbg.read_int32(p_msg + 4)

    return msg


def handler_DispatchMessageA(dbg):
    """
        parse param

        user32.DispatchMessageA

        DispatchMessageA-->DispatchMessageWorker

          _In_ const MSG *lpmsg
    """
    p_msg = dbg.read_stack_int32(4)
    code = parse_msg_params(dbg, p_msg)

    param_dict = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    _xrk_api_invoke_detail(dbg, "DispatchMessageA", param_dict)
    return param_dict


def handler_DispatchMessageW(dbg):
    """
        parse param

        user32.DispatchMessageW

        DispatchMessageW-->DispatchMessageWorker

          _In_ const MSG *lpmsg
    """
    p_msg = dbg.read_stack_int32(4)
    code = parse_msg_params(dbg, p_msg)

    param_dict = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    _xrk_api_invoke_detail(dbg, "DispatchMessageW", param_dict)
    return param_dict


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
    code = dbg.read_stack_int32(8)

    param_dict = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    _xrk_api_invoke_detail(dbg, "SendMessageA", param_dict)
    return param_dict


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
    code = dbg.read_stack_int32(8)

    param_dict = {"code": "%.8X-%s" % (code, msdn.resolve_code_win_msg(code))}
    _xrk_api_invoke_detail(dbg, "SendMessageW", param_dict)
    return param_dict


def handler_FindResourceA(dbg):
    """
        parse params

        kernel32.FindResourceA

        FindResourceA-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpName,
          _In_     LPCTSTR lpType
    """
    name = dbg.read_stack_p_ascii_string(8)
    if name is None or len(name) == 0:
        name = "%d(id)" % dbg.read_stack_int32(8)
    type_ = dbg.read_stack_p_ascii_string(0xC)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % dbg.read_stack_int32(0xC)

    param_dict = {"name": name, "type": type_}
    _xrk_api_invoke_detail(dbg, "FindResourceA", param_dict)
    return param_dict


def handler_FindResourceW(dbg):
    """
        parse params

        kernel32.FindResourceW

        FindResourceW-->LdrFindResource_U(ntdll)

          _In_opt_ HMODULE hModule,
          _In_     LPCTSTR lpName,
          _In_     LPCTSTR lpType
    """
    name = dbg.read_stack_p_unicode_string(8)
    if name is None or len(name) == 0:
        name = "%d(id)" % dbg.read_stack_int32(8)
    type_ = dbg.read_stack_p_unicode_string(0xC)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % dbg.read_stack_int32(0xC)

    param_dict = {"name": name, "type": type_}
    _xrk_api_invoke_detail(dbg, "FindResourceW", param_dict)
    return param_dict


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
    type_ = dbg.read_stack_p_ascii_string(8)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % dbg.read_stack_int32(8)
    name = dbg.read_stack_p_ascii_string(0xC)
    if name is None or len(name) == 0:
        name = "%d(id)" % dbg.read_stack_int32(0xC)

    param_dict = {"name": name, "type": type_}
    _xrk_api_invoke_detail(dbg, "FindResourceExA", param_dict)
    return param_dict


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
    type_ = dbg.read_stack_p_unicode_string(8)
    if type_ is None or len(type_) == 0:
        type_ = "%d(id)" % dbg.read_stack_int32(8)
    name = dbg.read_stack_p_unicode_string(0xC)
    if name is None or len(name) == 0:
        name = "%d(id)" % dbg.read_stack_int32(0xC)

    param_dict = {"name": name, "type": type_}
    _xrk_api_invoke_detail(dbg, "FindResourceExW", param_dict)
    return param_dict


def handler_ret_CreateMutexW(dbg):
    """
        change ret result
    """
    if dbg.context.Eax == 0:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "CreateMutexW", extrainfo="modify ret from 0 to 1")
            dbg.set_register("EAX", 1)

        else:
            _xrk_api_invoke_retn_detail(dbg, "CreateMutexW", extrainfo="intrude debugee not allowed, so we cancel it")

    dbg.bp_del(dbg.context.Eip)
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
    mutex = dbg.read_stack_p_unicode_string(0xC)

    global v_tmp_is_ignore_all_mutex
    global v_tmp_ignore_mutex_names
    if v_tmp_is_ignore_all_mutex or (v_tmp_ignore_mutex_names is not None and mutex in v_tmp_ignore_mutex_names):

        # set bp to modify ret of CreateMutexW
        # ret_offset: 0x0000E9C7 - 0x0000E947 = 0x80
        dbg.bp_set(dbg.context.Eip + 0x80, handler=handler_ret_CreateMutexW)

        # modify ret of GetLastError
        _set_GetLastError_ret_once(dbg, 0)

    param_dict = {"mutex": mutex}
    _xrk_api_invoke_detail(dbg, "CreateMutexW", param_dict)
    return param_dict


def handler_OpenMutexW(dbg):
    """
        might change ret result

        kernel32.OpenMutexW

        OpenMutexA-->OpenMutexW-->NtOpenMutant(ntdll)

          _In_ DWORD   dwDesiredAccess,
          _In_ BOOL    bInheritHandle,
          _In_ LPCTSTR lpName
    """
    mutex = dbg.read_stack_p_unicode_string(0xC)

    extrainfo = None
    global v_tmp_ignore_mutex_names
    if v_tmp_ignore_mutex_names is not None and mutex in v_tmp_ignore_mutex_names:
        extrainfo = "some interesting mutex name appears, u should pay attention to this"

    param_dict = {"mutex": mutex}
    _xrk_api_invoke_detail(dbg, "OpenMutexW", param_dict, extrainfo)
    return param_dict


def handler_ret_access(dbg):
    """
        modify result
    """
    global v_tmp_is_access_success
    assert v_tmp_is_access_success is True

    if dbg.context.Eax == 0xFFFFFFFF:

        global v_tmp_is_intrude_debugee
        if v_tmp_is_intrude_debugee:

            _xrk_api_invoke_retn_detail(dbg, "access", extrainfo="force ret from 0xFFFFFFFF to 0")
            dbg.set_register("EAX", 0)

        else:
            _xrk_api_invoke_retn_detail(dbg, "access", extrainfo="intrude debugee not allowed, so we cancel it.")

    global v_tmp_addr_access_rets
    assert v_tmp_addr_access_rets is not None and len(v_tmp_addr_access_rets) != 0
    for ret_addr in v_tmp_addr_access_rets:
        dbg.bp_del(ret_addr)

    return defines.DBG_CONTINUE


def handler_access(dbg):
    """
        might change ret result
    """
    path = dbg.read_stack_p_ascii_string(4)
    mode = dbg.read_stack_int32(8)

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

    global v_tmp_is_access_success
    if v_tmp_is_access_success:
        # start: 0000F355
        # tails:
        # 0000F379 - 0x24
        # 0000F39F - 0x4A
        offsets = [0x24, 0x4A]
        global v_tmp_addr_access_rets
        if v_tmp_addr_access_rets is None:
            v_tmp_addr_access_rets = []
            for offset in offsets:
                v_tmp_addr_access_rets.append(dbg.context.Eip + offset)

        for ret_addr in v_tmp_addr_access_rets:
            dbg.bp_set(ret_addr, handler=handler_ret_access)

    param_dict = {"path": path, "mode": mode_str}
    _xrk_api_invoke_detail(dbg, "access", param_dict)
    return param_dict


def handler_IsProcessorFeaturePresent(dbg):
    """
        parse params
    """
    feature = dbg.read_stack_int32(4)
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

    param_dict = {"feature": "%d-%s" % (feature, feature_str)}
    _xrk_api_invoke_detail(dbg, "IsProcessorFeaturePresent", param_dict)
    return param_dict


# ---------------------------------------------------------------------------
# func list
func_reg_advapi32 = [
    ApiHookLogParams("advapi32.dll", "RegCreateKeyExA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "RegCreateKeyExW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "RegConnectRegistryW", [ParamLogCtrl(4, "key", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookCustom("advapi32.dll", "RegSetValueExA", handler=handler_RegSetValueExA, cstk_filter_depth=2),
    ApiHookCustom("advapi32.dll", "RegSetValueExW", handler=handler_RegSetValueExW, cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "RegDeleteKeyA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "RegDeleteKeyW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "RegDeleteValueA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "RegDeleteValueW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "RegSaveKeyExA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "RegSaveKeyExW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "RegSaveKeyA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "RegSaveKeyW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "RegReplaceKeyA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "file_new", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "file_old", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "RegReplaceKeyW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "file_new", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "file_old", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "RegRestoreKeyA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "RegRestoreKeyW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "RegLoadKeyA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "RegLoadKeyW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)]),
]

func_reg_advapi32_fragile = [
    ApiHookLogParams("advapi32.dll", "RegOpenKeyExA", [ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "RegOpenKeyExW", [ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "RegQueryInfoKeyA", max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegQueryInfoKeyW", max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegQueryMultipleValuesA", max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegQueryMultipleValuesW", max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegQueryValueExA", [ParamLogCtrl(8, "vname", V_PARAM_LOG_PASTR)], cstk_filter_depth=2, max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegQueryValueExW", [ParamLogCtrl(8, "vname", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2, max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegEnumKeyExA", cstk_filter_depth=2, max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegEnumKeyW", max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegEnumKeyExW", max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegEnumValueA", max_invoke_cnt_runtime=10),
    ApiHookLogParams("advapi32.dll", "RegEnumValueW", max_invoke_cnt_runtime=10),
]

func_dns_dnsapi = [
    ApiHookLogParams("dnsapi.dll", "DnsQuery_W", [ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)], cstk_filter_depth=4),
    ApiHookLogParams("dnsapi.dll", "DnsQuery_UTF8", [ParamLogCtrl(4, "name", V_PARAM_LOG_PASTR)]),
]

func_sock_ws2_32 = [
    ApiHookLogParams("ws2_32.dll", "WSAStartup"),
    ApiHookLogParams("ws2_32.dll", "WSACleanup"),
    ApiHookCustom("ws2_32.dll", "WSASocketW", handler=handler_WSASocketW, cstk_filter_depth=2),
    ApiHookLogParams("ws2_32.dll", "closesocket"),
    ApiHookLogParams("ws2_32.dll", "getnameinfo"),
    ApiHookLogParams("ws2_32.dll", "GetNameInfoW"),
    ApiHookCustom("ws2_32.dll", "getsockname", handler=handler_getsockname),
    ApiHookLogParams("ws2_32.dll", "getpeername"),
    ApiHookCustom("ws2_32.dll", "gethostname", handler=handler_gethostname),
    ApiHookLogParams("ws2_32.dll", "gethostbyaddr"),
    ApiHookCustom("ws2_32.dll", "gethostbyname", handler=handler_gethostbyname),
    ApiHookLogParams("ws2_32.dll", "getaddrinfo", [ParamLogCtrl(4, "node", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "svc", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("ws2_32.dll", "GetAddrInfoW", [ParamLogCtrl(4, "node", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "svc", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("ws2_32.dll", "freeaddrinfo"),
    ApiHookCustom("ws2_32.dll", "bind", handler=handler_bind),
    ApiHookLogParams("ws2_32.dll", "listen"),
    ApiHookCustom("ws2_32.dll", "connect", handler=handler_connect),
    ApiHookCustom("ws2_32.dll", "send", handler=handler_send),
    ApiHookCustom("ws2_32.dll", "sendto", handler=handler_sendto),
    ApiHookCustom("ws2_32.dll", "recv", handler=handler_recv),
    ApiHookCustom("ws2_32.dll", "recvfrom", handler=handler_recvfrom),
    ApiHookCustom("ws2_32.dll", "select", handler=handler_select),
    ApiHookCustom("ws2_32.dll", "setsockopt", handler=handler_setsockopt),
]

func_sock_ws2_32_WSA = [
    ApiHookLogParams("ws2_32.dll", "WSAAccept", cstk_filter_depth=2),
    ApiHookCustom("ws2_32.dll", "WSASend", handler=handler_WSASend),
    ApiHookCustom("ws2_32.dll", "WSASendTo", handler=handler_WSASendTo),
    ApiHookCustom("ws2_32.dll", "WSAConnect", handler=handler_WSAConnect),
    ApiHookLogParams("ws2_32.dll", "WSASendDisconnect"),
    ApiHookCustom("ws2_32.dll", "WSARecv", handler=handler_WSARecv),
    ApiHookCustom("ws2_32.dll", "WSARecvFrom", handler=handler_WSARecvFrom),
    ApiHookLogParams("ws2_32.dll", "WSARecvDisconnect"),
]

func_internet_wininet = [
    ApiHookLogParams("wininet.dll", "InternetOpenA", [ParamLogCtrl(4, "agent", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "proxy_name", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "proxy_pwd", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookCustom("wininet.dll", "InternetConnectA", handler=handler_InternetConnectA, cstk_filter_depth=2),
    ApiHookLogParams("wininet.dll", "InternetCrackUrlA", [ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("wininet.dll", "InternetOpenUrlA", [ParamLogCtrl(8, "url", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "headers", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("wininet.dll", "InternetReadFile"),
    ApiHookLogParams("wininet.dll", "InternetReadFileExA", cstk_filter_depth=2),
    ApiHookLogParams("wininet.dll", "InternetWriteFile"),
    ApiHookLogParams("wininet.dll", "HttpOpenRequestA", [ParamLogCtrl(8, "verb", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "obj", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "ver", V_PARAM_LOG_PASTR), ParamLogCtrl(0x14, "refer", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("wininet.dll", "HttpOpenRequestW", [ParamLogCtrl(8, "verb", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "obj", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "ver", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x14, "refer", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("wininet.dll", "HttpSendRequestA", [ParamLogCtrl(8, "headers", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "opt", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("wininet.dll", "HttpSendRequestW", [ParamLogCtrl(8, "headers", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "opt", V_PARAM_LOG_PUSTR)]),
    ApiHookCustom("wininet.dll", "HttpSendRequestExA", handler=handler_HttpSendRequestExA),
    ApiHookCustom("wininet.dll", "HttpSendRequestExW", handler=handler_HttpSendRequestExW),
    ApiHookLogParams("wininet.dll", "HttpAddRequestHeadersA", cstk_filter_depth=2),
]

func_internet_wininet_1 = [
    ApiHookLogParams("wininet.dll", "InternetFindNextFileA", cstk_filter_depth=2),
    ApiHookLogParams("wininet.dll", "InternetGetCookieExW", [ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "coockie", V_PARAM_LOG_PUSTR)], cstk_filter_depth=3),
    ApiHookLogParams("wininet.dll", "InternetSetCookieA", [ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "coockie_name", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "coockie_data", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("wininet.dll", "InternetSetCookieExA", [ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "coockie_name", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "coockie_data", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("wininet.dll", "InternetSetCookieExW", [ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "coockie_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "coockie_data", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("wininet.dll", "InternetAttemptConnect"),
    ApiHookLogParams("wininet.dll", "InternetCanonicalizeUrlA", [ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("wininet.dll", "InternetCanonicalizeUrlW", [ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("wininet.dll", "DeleteUrlCacheEntryA", [ParamLogCtrl(4, "url", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
]

func_internet_winhttp = [
    ApiHookLogParams("winhttp.dll", "WinHttpOpen", [ParamLogCtrl(4, "agent", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "proxy_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "proxy_pwd", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("winhttp.dll", "WinHttpCloseHandle"),
    ApiHookLogParams("winhttp.dll", "WinHttpConnect", [ParamLogCtrl(8, "svr_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "svr_port", V_PARAM_LOG_INT)]),
    ApiHookLogParams("winhttp.dll", "WinHttpOpenRequest", [ParamLogCtrl(8, "verb", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "obj", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "ver", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x14, "refer", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x18, "acept_type", V_PARAM_LOG_PPUSTR)]),
    ApiHookLogParams("winhttp.dll", "WinHttpSendRequest", [ParamLogCtrl(8, "headers", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("winhttp.dll", "WinHttpReceiveResponse"),
    ApiHookLogParams("winhttp.dll", "WinHttpQueryHeaders", [ParamLogCtrl(0xC, "name", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("winhttp.dll", "WinHttpQueryDataAvailable"),
    ApiHookLogParams("winhttp.dll", "WinHttpReadData"),
    ApiHookLogParams("winhttp.dll", "WinHttpAddRequestHeaders", [ParamLogCtrl(8, "headers", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("winhttp.dll", "WinHttpCrackUrl", [ParamLogCtrl(4, "url", V_PARAM_LOG_PUSTR)]),
    ApiHookCustom("winhttp.dll", "WinHttpCreateUrl", handler=handler_WinHttpCreateUrl),
    ApiHookCustom("winhttp.dll", "WinHttpWriteData", handler=handler_WinHttpWriteData),
]

func_internet_urlmon = [
    ApiHookLogParams("urlmon.dll", "URLDownloadW", [ParamLogCtrl(8, "url", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("urlmon.dll", "URLDownloadToFileW", [ParamLogCtrl(8, "url", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("urlmon.dll", "URLDownloadToCacheFileW", [ParamLogCtrl(8, "url", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
]

func_internet_rasapi32 = [
    ApiHookLogParams("rasapi32.dll", "RasGetConnectStatusW", cstk_filter_depth=2),
]

func_proc_kernel32 = [
    ApiHookCustom("kernel32.dll", "IsWow64Process", handler=handler_IsWow64Process),
    ApiHookCustom("kernel32.dll", "CreateProcessInternalW", handler=handler_CreateProcessInternalW, cstk_filter_depth=3),
    ApiHookCustom("kernel32.dll", "CreateRemoteThread", handler=handler_CreateRemoteThread, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "OpenProcess", handler=handler_OpenProcess),
    ApiHookCustom("kernel32.dll", "GetExitCodeProcess", handler=handler_GetExitCodeProcess),
    ApiHookLogParams("kernel32.dll", "OpenThread", [ParamLogCtrl(4, "tid", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "TerminateThread", [ParamLogCtrl(8, "code", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "SuspendThread"),
    ApiHookLogParams("kernel32.dll", "ResumeThread"),
    ApiHookLogParams("kernel32.dll", "ExitThread", [ParamLogCtrl(4, "code", V_PARAM_LOG_INT)]),
]

func_proc_kernel32_1 = [
    ApiHookCustom("kernel32.dll", "SetThreadContext", handler=handler_SetThreadContext),
    ApiHookCustom("kernel32.dll", "GetThreadContext", handler=handler_GetThreadContext),
    ApiHookCustom("kernel32.dll", "ReadProcessMemory", handler=handler_ReadProcessMemory, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "WriteProcessMemory", handler=handler_WriteProcessMemory),
    ApiHookCustom("kernel32.dll", "CreateToolhelp32Snapshot", handler=handler_CreateToolhelp32Snapshot),
]

func_proc_kernel32_2 = [
    ApiHookLogParams("kernel32.dll", "Process32FirstW", cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "Process32NextW", cstk_filter_depth=2, max_invoke_cnt_runtime=10),
    ApiHookLogParams("kernel32.dll", "Module32FirstW", cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "Module32NextW", cstk_filter_depth=2, max_invoke_cnt_runtime=10),
    ApiHookLogParams("kernel32.dll", "Thread32First"),
    ApiHookLogParams("kernel32.dll", "Thread32Next", max_invoke_cnt_runtime=10),
]

func_file_kernel32 = [
    ApiHookCustom("kernel32.dll", "CreateFileMappingW", handler=handler_CreateFileMappingW, cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "MapViewOfFileEx"),
    ApiHookCustom("kernel32.dll", "UnmapViewOfFile", handler=handler_UnmapViewOfFile),
    ApiHookCustom("kernel32.dll", "CreateFileW", handler=handler_CreateFileW, cstk_filter_depth=3),
    ApiHookLogParams("kernel32.dll", "ReadFile", cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "ReadFileEx"),
    ApiHookCustom("kernel32.dll", "WriteFile", handler=handler_WriteFile, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "WriteFileEx", handler=handler_WriteFileEx),
    ApiHookLogParams("kernel32.dll", "CopyFileExW", [ParamLogCtrl(4, "file_old", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "file_new", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "MoveFileWithProgressW", handler=handler_MoveFileWithProgressW, cstk_filter_depth=3),
    ApiHookLogParams("kernel32.dll", "CreateDirectoryW", [ParamLogCtrl(4, "dir", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "CreateDirectoryExW", [ParamLogCtrl(4, "dir_template", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "dir_new", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "RemoveDirectoryW", handler=handler_RemoveDirectoryW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "ReplaceFileW", handler=handler_ReplaceFileW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "DeleteFileW", handler=handler_DeleteFileW, cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "DeviceIoControl", [ParamLogCtrl(8, "code", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "FindFirstFileExW", [ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "SetFileAttributesW", handler=handler_SetFileAttributesW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "SetFileTime", handler=handler_SetFileTime),
    ApiHookLogParams("kernel32.dll", "GetFileTime"),
    ApiHookLogParams("kernel32.dll", "GetFileSizeEx", cstk_filter_depth=2),

    ApiHookCustom("kernel32.dll", "GetTempPathW", handler=handler_GetTempPathW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetTempFileNameW", handler=handler_GetTempFileNameW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetSystemDirectoryA", handler=handler_GetSystemDirectoryA),
    ApiHookCustom("kernel32.dll", "GetSystemDirectoryW", handler=handler_GetSystemDirectoryW),
]

func_file_kernel32_1 = [
    ApiHookLogParams("kernel32.dll", "GetDiskFreeSpaceW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "GetDiskFreeSpaceExW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "GetDriveTypeW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "GetVolumeInformationW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "GetVolumeNameForVolumeMountPointW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "FindFirstVolumeW", cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "FindNextVolumeW", cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetFullPathNameW", handler=handler_GetFullPathNameW, cstk_filter_depth=3),
    ApiHookLogParams("kernel32.dll", "GetVolumePathNamesForVolumeNameW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "GetLogicalDriveStringsA"),
    ApiHookLogParams("kernel32.dll", "GetLogicalDriveStringsW"),
    ApiHookLogParams("kernel32.dll", "GetLogicalDrives"),
    ApiHookLogParams("kernel32.dll", "FindNextFileW", cstk_filter_depth=2, max_invoke_cnt_runtime=10),
    ApiHookLogParams("kernel32.dll", "SetDllDirectoryA", [ParamLogCtrl(4, "dir", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "SetDllDirectoryW", [ParamLogCtrl(4, "dir", V_PARAM_LOG_PUSTR)]),

    # cause sample D0B78005C40EFC219CC1299A57B85C03 HANG
    ApiHookLogParams("kernel32.dll", "OpenFileMappingW", [ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
]

func_file_shlwapi = [
    ApiHookLogParams("shlwapi.dll", "PathFileExistsA", [ParamLogCtrl(4, "path", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("shlwapi.dll", "PathFileExistsW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("shlwapi.dll", "PathRemoveFileSpecA", [ParamLogCtrl(4, "path", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("shlwapi.dll", "PathRemoveFileSpecW", [ParamLogCtrl(4, "path", V_PARAM_LOG_PUSTR)]),
]

func_svc_advapi32 = [
    ApiHookLogParams("advapi32.dll", "OpenSCManagerA", [ParamLogCtrl(4, "machine", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "database", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "OpenSCManagerW", [ParamLogCtrl(4, "machine", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "database", V_PARAM_LOG_PUSTR)]),
    ApiHookCustom("advapi32.dll", "CreateServiceA", handler=handler_CreateServiceA),
    ApiHookCustom("advapi32.dll", "CreateServiceW", handler=handler_CreateServiceW),
    ApiHookCustom("advapi32.dll", "ControlService", handler=handler_ControlService),
    ApiHookLogParams("advapi32.dll", "DeleteService"),
    ApiHookLogParams("advapi32.dll", "GetServiceDisplayNameA", [ParamLogCtrl(8, "svc", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "GetServiceDisplayNameW", [ParamLogCtrl(8, "svc", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "GetServiceKeyNameA", [ParamLogCtrl(8, "display_name", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "GetServiceKeyNameW", [ParamLogCtrl(8, "display_name", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "OpenServiceA", [ParamLogCtrl(8, "svc", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "OpenServiceW", [ParamLogCtrl(8, "svc", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "RegisterServiceCtrlHandlerW", [ParamLogCtrl(4, "svc", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "RegisterServiceCtrlHandlerExW", [ParamLogCtrl(4, "svc", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "StartServiceA"),
    ApiHookLogParams("advapi32.dll", "StartServiceW"),
    ApiHookCustom("advapi32.dll", "StartServiceCtrlDispatcherA", handler=handler_StartServiceCtrlDispatcherA),
    ApiHookCustom("advapi32.dll", "StartServiceCtrlDispatcherW", handler=handler_StartServiceCtrlDispatcherW),
]

func_crypto_advapi32 = [
    ApiHookLogParams("advapi32.dll", "CryptAcquireContextA", [ParamLogCtrl(4, "container", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "provider", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "CryptReleaseContext"),
]

func_crypto_advapi32_1 = [
    ApiHookLogParams("advapi32.dll", "CryptSetProvParam"),
    ApiHookLogParams("advapi32.dll", "CryptGetProvParam"),
    ApiHookLogParams("advapi32.dll", "CryptCreateHash"),
    ApiHookLogParams("advapi32.dll", "CryptHashData"),
    ApiHookLogParams("advapi32.dll", "CryptGetHashParam"),
    ApiHookLogParams("advapi32.dll", "CryptSetHashParam"),
    ApiHookLogParams("advapi32.dll", "CryptHashSessionKey"),
    ApiHookLogParams("advapi32.dll", "CryptDestroyHash"),
    ApiHookLogParams("advapi32.dll", "CryptGenRandom"),
    ApiHookLogParams("advapi32.dll", "CryptDeriveKey"),
    ApiHookLogParams("advapi32.dll", "CryptGenKey"),
    ApiHookLogParams("advapi32.dll", "CryptDestroyKey"),
    ApiHookLogParams("advapi32.dll", "CryptImportKey"),
    ApiHookLogParams("advapi32.dll", "CryptExportKey"),
    ApiHookLogParams("advapi32.dll", "CryptGetKeyParam"),
    ApiHookLogParams("advapi32.dll", "CryptSetKeyParam"),
    ApiHookLogParams("advapi32.dll", "CryptGetUserKey"),
    ApiHookLogParams("advapi32.dll", "CryptSignHashA"),
    ApiHookLogParams("advapi32.dll", "CryptSignHashW"),
    ApiHookLogParams("advapi32.dll", "CryptVerifySignatureA"),
    ApiHookLogParams("advapi32.dll", "CryptVerifySignatureW"),
    ApiHookLogParams("advapi32.dll", "CryptEncrypt"),
    ApiHookLogParams("advapi32.dll", "CryptDecrypt"),
    ApiHookLogParams("advapi32.dll", "CryptDuplicateHash"),
    ApiHookLogParams("advapi32.dll", "CryptDuplicateKey"),
]

func_str_kernel32 = [
    ApiHookLogParams("kernel32.dll", "lstrcatA", [ParamLogCtrl(4, "str1", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "str2", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "lstrcatW", [ParamLogCtrl(4, "str1", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "str2", V_PARAM_LOG_PUSTR)]),
    ApiHookCustom("kernel32.dll", "lstrcmpA", handler=handler_lstrcmpA),
    ApiHookCustom("kernel32.dll", "lstrcmpW", handler=handler_lstrcmpW),
    ApiHookCustom("kernel32.dll", "lstrcmpiA", handler=handler_lstrcmpiA),
    ApiHookCustom("kernel32.dll", "lstrcmpiW", handler=handler_lstrcmpiW),
    ApiHookLogParams("kernel32.dll", "lstrcpyA", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "lstrcpyW", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("kernel32.dll", "lstrcpynA", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "len", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "lstrcpynW", [ParamLogCtrl(8, "str2", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "len", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "lstrlenA", [ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "lstrlenW", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
]

func_str_shlwapi = [
    # todo: there are 2 deeper functions: wvnsprintfA/W
    ApiHookCustom("shlwapi.dll", "wnsprintfA", handler=handler_wnsprintfA, cstk_filter_depth=2),
    ApiHookCustom("shlwapi.dll", "wnsprintfW", handler=handler_wnsprintfW, cstk_filter_depth=2),
]

func_str_ntdll = [
    # bp at these apis will result in unknow results...
    ApiHookLogParams("ntdll.dll", "RtlInitString", [ParamLogCtrl(8, "str", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("ntdll.dll", "RtlInitAnsiString", [ParamLogCtrl(8, "str", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("ntdll.dll", "RtlInitUnicodeString", [ParamLogCtrl(8, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("ntdll.dll", "RtlInitUnicodeStringEx", [ParamLogCtrl(8, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("ntdll.dll", "RtlIsDosDeviceName_U", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("ntdll.dll", "RtlDosPathNameToNtPathName_U", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("ntdll.dll", "RtlDetermineDosPathNameType_U"),
]

func_win_user32 = [
    ApiHookLogParams("user32.dll", "FindWindowA", [ParamLogCtrl(4, "class_name", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "win_name", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("user32.dll", "FindWindowW", [ParamLogCtrl(4, "class_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "win_name", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("user32.dll", "FindWindowExA", [ParamLogCtrl(0xC, "class_name", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "win_name", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("user32.dll", "FindWindowExW", [ParamLogCtrl(0xC, "class_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "win_name", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("user32.dll", "GetDesktopWindow"),

    ApiHookLogParams("user32.dll", "DialogBoxParamA", [ParamLogCtrl(8, "template", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "DialogBoxParamW", [ParamLogCtrl(8, "template", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "MessageBoxTimeoutW", [ParamLogCtrl(8, "txt", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "caption", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x18, "mescs", V_PARAM_LOG_INT)], cstk_filter_depth=4),
    ApiHookCustom("user32.dll", "MessageBoxIndirectA", handler=handler_MessageBoxIndirectA),
    ApiHookCustom("user32.dll", "MessageBoxIndirectW", handler=handler_MessageBoxIndirectW),
    ApiHookCustom("user32.dll", "RegisterClassA", handler=handler_RegisterClassA),
    ApiHookCustom("user32.dll", "RegisterClassW", handler=handler_RegisterClassW),
    ApiHookCustom("user32.dll", "RegisterClassExA", handler=handler_RegisterClassExA),
    ApiHookCustom("user32.dll", "RegisterClassExW", handler=handler_RegisterClassExW),
    ApiHookLogParams("user32.dll", "PostQuitMessage", [ParamLogCtrl(4, "code", V_PARAM_LOG_INT)]),
]

func_win_user32_2 = [
    ApiHookLogParams("user32.dll", "CreateWindowExA", [ParamLogCtrl(8, "class", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "win", V_PARAM_LOG_PASTR), ParamLogCtrl(0x14, "x", V_PARAM_LOG_INT), ParamLogCtrl(0x18, "y", V_PARAM_LOG_INT), ParamLogCtrl(0x1C, "width", V_PARAM_LOG_INT), ParamLogCtrl(0x20, "height", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "CreateWindowExW", [ParamLogCtrl(8, "class", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x14, "x", V_PARAM_LOG_INT), ParamLogCtrl(0x18, "y", V_PARAM_LOG_INT), ParamLogCtrl(0x1C, "width", V_PARAM_LOG_INT), ParamLogCtrl(0x20, "height", V_PARAM_LOG_INT)]),
]

func_win_user32_1 = [
    ApiHookLogParams("user32.dll", "EnumWindows", [ParamLogCtrl(4, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "EnumChildWindows", [ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "EnumDesktopWindows", [ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "EnumDesktopsA", [ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "EnumDesktopsW", [ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "EnumDisplayDevicesA", [ParamLogCtrl(4, "file", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("user32.dll", "EnumDisplayDevicesW", [ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)]),

    ApiHookLogParams("user32.dll", "CreateWindowStationA", [ParamLogCtrl(4, "win", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("user32.dll", "CreateWindowStationW", [ParamLogCtrl(4, "win", V_PARAM_LOG_PUSTR)]),

    ApiHookCustom("user32.dll", "DispatchMessageA", handler=handler_DispatchMessageA),
    ApiHookCustom("user32.dll", "DispatchMessageW", handler=handler_DispatchMessageW),
    ApiHookLogParams("user32.dll", "PeekMessageA"),
    ApiHookLogParams("user32.dll", "PeekMessageW"),
    ApiHookCustom("user32.dll", "PostMessageA", handler=handler_PostMessageA),
    ApiHookCustom("user32.dll", "PostMessageW", handler=handler_PostMessageW),
    ApiHookCustom("user32.dll", "SendMessageA", handler=handler_SendMessageA),
    ApiHookCustom("user32.dll", "SendMessageW", handler=handler_SendMessageW),
    ApiHookLogParams("user32.dll", "RegisterServicesProcess", [ParamLogCtrl(4, "pid", V_PARAM_LOG_INT)]),

    ApiHookLogParams("user32.dll", "SetProcessWindowStation"),
    ApiHookLogParams("user32.dll", "OpenDesktopA", [ParamLogCtrl(8, "desktop", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("user32.dll", "OpenDesktopW", [ParamLogCtrl(8, "desktop", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("user32.dll", "SetThreadDesktop"),
    ApiHookLogParams("user32.dll", "OpenWindowStationA", [ParamLogCtrl(8, "station", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("user32.dll", "OpenWindowStationW", [ParamLogCtrl(8, "station", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("user32.dll", "EmptyClipboard"),
    ApiHookLogParams("user32.dll", "GetClipboardData"),
    ApiHookLogParams("user32.dll", "OpenClipboard"),
    ApiHookLogParams("user32.dll", "SetClipboardData"),
    ApiHookLogParams("user32.dll", "GetKeyboardState"),
    ApiHookLogParams("user32.dll", "SetKeyboardState"),
    ApiHookLogParams("user32.dll", "GetAsyncKeyState"),
    ApiHookLogParams("user32.dll", "GetKeyState"),
    ApiHookLogParams("user32.dll", "keybd_event"),
    ApiHookLogParams("user32.dll", "mouse_event"),
    ApiHookLogParams("user32.dll", "GetCursorPos"),
    ApiHookLogParams("user32.dll", "GetWindowRect"),
    ApiHookLogParams("user32.dll", "ScreenToClient"),
    ApiHookLogParams("user32.dll", "ClientToScreen"),
    ApiHookLogParams("user32.dll", "GetForegroundWindow"),
]

func_win_gdi32 = [
    ApiHookLogParams("gdi32.dll", "CreateCompatibleDC"),
    ApiHookLogParams("gdi32.dll", "CreateCompatibleBitmap"),
    ApiHookLogParams("gdi32.dll", "BitBlt"),
]

func_mutex_kernel32 = [
    ApiHookLogParams("kernel32.dll", "ReleaseMutex"),
    ApiHookCustom("kernel32.dll", "CreateMutexW", handler=handler_CreateMutexW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "OpenMutexW", handler=handler_OpenMutexW, cstk_filter_depth=2),
]

func_evtlog_advapi32 = [
    ApiHookLogParams("advapi32.dll", "OpenEventLogA", [ParamLogCtrl(4, "svr", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "src", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("advapi32.dll", "OpenEventLogW", [ParamLogCtrl(4, "svr", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "src", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("advapi32.dll", "ClearEventLogW", [ParamLogCtrl(8, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
]

func_priviledge_advapi32 = [
    ApiHookLogParams("advapi32.dll", "AdjustTokenPrivileges"),
    ApiHookLogParams("advapi32.dll", "LookupPrivilegeDisplayNameW", [ParamLogCtrl(4, "sys", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "name", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "LookupPrivilegeNameW", [ParamLogCtrl(4, "sys", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "LookupPrivilegeValueW", [ParamLogCtrl(4, "sys", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "name", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
]

func_res_kernel32 = [
    ApiHookCustom("kernel32.dll", "FindResourceA", handler=handler_FindResourceA),
    ApiHookCustom("kernel32.dll", "FindResourceW", handler=handler_FindResourceW),
    ApiHookCustom("kernel32.dll", "FindResourceExA", handler=handler_FindResourceExA),
    ApiHookCustom("kernel32.dll", "FindResourceExW", handler=handler_FindResourceExW),
    ApiHookLogParams("kernel32.dll", "LoadResource"),
    ApiHookLogParams("kernel32.dll", "LockResource"),
    ApiHookLogParams("kernel32.dll", "SizeofResource"),
]

func_res_kernel32_1 = [
    ApiHookLogParams("kernel32.dll", "UpdateResourceW", [ParamLogCtrl(8, "res_type", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "res_name", V_PARAM_LOG_PUSTR)]),
]

func_pipe_kernel32 = [
    ApiHookLogParams("kernel32.dll", "CreateNamedPipeW", [ParamLogCtrl(4, "pipe", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "CreatePipe"),
]

func_pipe_kernel32_1 = [
    ApiHookLogParams("kernel32.dll", "CallNamedPipeW", [ParamLogCtrl(4, "pipe", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "WaitNamedPipeW", [ParamLogCtrl(4, "pipe", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "PeekNamedPipe"),
    ApiHookLogParams("kernel32.dll", "ConnectNamedPipe"),
    ApiHookLogParams("kernel32.dll", "DisconnectNamedPipe"),
]

func_hook_user32 = [
    ApiHookLogParams("user32.dll", "SetWindowsHookA", [ParamLogCtrl(4, "id", V_PARAM_LOG_INT), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "SetWindowsHookW", [ParamLogCtrl(4, "id", V_PARAM_LOG_INT), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "SetWindowsHookExA", [ParamLogCtrl(4, "id", V_PARAM_LOG_INT), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT), ParamLogCtrl(0x10, "tid", V_PARAM_LOG_INT)], cstk_filter_depth=2),
    ApiHookLogParams("user32.dll", "SetWindowsHookExW", [ParamLogCtrl(4, "id", V_PARAM_LOG_INT), ParamLogCtrl(8, "cbk", V_PARAM_LOG_INT), ParamLogCtrl(0x10, "tid", V_PARAM_LOG_INT)], cstk_filter_depth=2),
]

func_hook_user32_1 = [
    ApiHookLogParams("user32.dll", "CallNextHookEx", [ParamLogCtrl(8, "code", V_PARAM_LOG_INT)]),
    ApiHookLogParams("user32.dll", "UnhookWindowsHook", [ParamLogCtrl(4, "code", V_PARAM_LOG_INT)]),
]

func_environment_kernel32 = [
    ApiHookLogParams("kernel32.dll", "GetEnvironmentStringsA"),
    ApiHookLogParams("kernel32.dll", "GetEnvironmentStringsW"),
    ApiHookLogParams("kernel32.dll", "GetEnvironmentVariableA", [ParamLogCtrl(4, "name", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "GetEnvironmentVariableW", [ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("kernel32.dll", "SetEnvironmentVariableA", [ParamLogCtrl(4, "name", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "value", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "SetEnvironmentVariableW", [ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "value", V_PARAM_LOG_PUSTR)]),
    ApiHookCustom("kernel32.dll", "ExpandEnvironmentStringsA", handler=handler_ExpandEnvironmentStringsA),
    ApiHookCustom("kernel32.dll", "ExpandEnvironmentStringsW", handler=handler_ExpandEnvironmentStringsW),
]

func_profile_kernel32 = [
    ApiHookCustom("kernel32.dll", "GetPrivateProfileStringA", handler=handler_GetPrivateProfileStringA, cstk_filter_depth=3),
    ApiHookCustom("kernel32.dll", "GetPrivateProfileStringW", handler=handler_GetPrivateProfileStringW, cstk_filter_depth=3),
    ApiHookLogParams("kernel32.dll", "GetPrivateProfileSectionA", [ParamLogCtrl(4, "app_name", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "file", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "GetPrivateProfileSectionW", [ParamLogCtrl(4, "app_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "WritePrivateProfileSectionA", [ParamLogCtrl(4, "app_name", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "value", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "WritePrivateProfileSectionW", [ParamLogCtrl(4, "app_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "value", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "WritePrivateProfileStringA", [ParamLogCtrl(4, "app_name", V_PARAM_LOG_PASTR), ParamLogCtrl(8, "key", V_PARAM_LOG_PASTR), ParamLogCtrl(0xC, "value", V_PARAM_LOG_PASTR), ParamLogCtrl(0x10, "file", V_PARAM_LOG_PASTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "WritePrivateProfileStringW", [ParamLogCtrl(4, "app_name", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "key", V_PARAM_LOG_PUSTR), ParamLogCtrl(0xC, "value", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
]

func_event_kernel32 = [
    ApiHookLogParams("kernel32.dll", "OpenEventW", [ParamLogCtrl(0xC, "evt", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "SetEvent"),
    ApiHookLogParams("kernel32.dll", "ResetEvent"),
    ApiHookLogParams("kernel32.dll", "PulseEvent"),
]

func_timer_user32 = [
    ApiHookCustom("user32.dll", "SetTimer", handler=handler_SetTimer),
    ApiHookLogParams("user32.dll", "SetSystemTimer"),
    ApiHookCustom("user32.dll", "KillTimer", handler=handler_KillTimer),
    ApiHookLogParams("user32.dll", "KillSystemTimer"),
]

func_atom_kernel32 = [
    ApiHookLogParams("kernel32.dll", "InitAtomTable", [ParamLogCtrl(4, "size", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "AddAtomA", [ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "AddAtomW", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("kernel32.dll", "DeleteAtom"),
    ApiHookLogParams("kernel32.dll", "FindAtomA", [ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "FindAtomW", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("kernel32.dll", "GetAtomNameA"),
    ApiHookLogParams("kernel32.dll", "GetAtomNameW"),
    ApiHookLogParams("kernel32.dll", "GlobalAddAtomA", [ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "GlobalAddAtomW", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("kernel32.dll", "GlobalDeleteAtom"),
    ApiHookLogParams("kernel32.dll", "GlobalFindAtomA", [ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)]),
    ApiHookLogParams("kernel32.dll", "GlobalFindAtomW", [ParamLogCtrl(4, "str", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("kernel32.dll", "GlobalGetAtomNameA"),
    ApiHookLogParams("kernel32.dll", "GlobalGetAtomNameW"),
]

func_com_ole32 = [
    ApiHookLogParams("ole32.dll", "CoInitializeEx"),
]

func_com_ole32_1 = [
    ApiHookLogParams("ole32.dll", "CoCreateInstanceEx"),
    ApiHookLogParams("ole32.dll", "CoUninitialize"),
]

func_mm_kernel32 = [
    ApiHookCustom("kernel32.dll", "VirtualAllocEx", handler=handler_VirtualAllocEx, cstk_filter_depth=2),
]

func_mm_kernel32_1 = [
    # bp at this api will result in unknown results...
    # ApiHookLogParams("kernel32.dll", "TlsAlloc"),
    ApiHookCustom("kernel32.dll", "VirtualProtectEx", handler=handler_VirtualProtectEx, cstk_filter_depth=2),
]

func_mm_ntdll = [
    ApiHookLogParams("ntdll.dll", "RtlReAllocateHeap", [ParamLogCtrl(0x10, "size", V_PARAM_LOG_INT)]),
]

func_dotnet_mscoree = [
    # manual load .NET module
    ApiHookLogParams("mscoree.dll", "CLRCreateInstance", [ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("mscoree.dll", "CorBindToRuntimeEx", [ParamLogCtrl(4, "version", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "flavor", V_PARAM_LOG_PUSTR)]),
    ApiHookLogParams("mscoree.dll", "CorExitProcess"),
]

func_other_dbghelp = [
    ApiHookCustom("dbghelp.dll", "MiniDumpWriteDump", handler=handler_MiniDumpWriteDump),
    ApiHookLogParams("dbghelp.dll", "StackWalk64"),
    ApiHookLogParams("dbghelp.dll", "SymFunctionTableAccess64"),
    ApiHookLogParams("dbghelp.dll", "SymGetModuleBase64"),
]

func_other_kernel32 = [
    ApiHookCustom("kernel32.dll", "GetProcAddress", handler=handler_GetProcAddress),
    ApiHookLogParams("kernel32.dll", "LoadLibraryExW", [ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=3),
    ApiHookLogParams("kernel32.dll", "IsDebuggerPresent"),

    ApiHookCustom("kernel32.dll", "SetErrorMode", handler=handler_SetErrorMode),
    ApiHookLogParams("kernel32.dll", "SetUnhandledExceptionFilter", [ParamLogCtrl(4, "cbk", V_PARAM_LOG_INT)]),
    ApiHookCustom("kernel32.dll", "GetComputerNameW", handler=handler_GetComputerNameW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetComputerNameExW", handler=handler_GetComputerNameExW, cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "SetComputerNameW", [ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "SetComputerNameExW", [ParamLogCtrl(8, "name", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetCurrentDirectoryA", handler=handler_GetCurrentDirectoryA),
    ApiHookCustom("kernel32.dll", "GetCurrentDirectoryW", handler=handler_GetCurrentDirectoryW),
    ApiHookCustom("kernel32.dll", "GetModuleFileNameW", handler=handler_GetModuleFileNameW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetVersion", handler=handler_GetVersion),
    ApiHookCustom("kernel32.dll", "GetVersionExW", handler=handler_GetVersionExW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetCommandLineA", handler=handler_GetCommandLineA),
    ApiHookCustom("kernel32.dll", "GetCommandLineW", handler=handler_GetCommandLineW),
    ApiHookLogParams("kernel32.dll", "GetStartupInfoA"),
    ApiHookLogParams("kernel32.dll", "GetStartupInfoW"),
    ApiHookLogParams("kernel32.dll", "OutputDebugStringA", [ParamLogCtrl(4, "str", V_PARAM_LOG_PASTR)], cstk_filter_depth=2, max_invoke_cnt_runtime=100),

    ApiHookCustom("kernel32.dll", "GetTickCount", handler=handler_GetTickCount, max_invoke_cnt_runtime=50),
    ApiHookCustom("kernel32.dll", "GetSystemTime", handler=handler_GetSystemTime),
]

func_other_kernel32_1 = [
    ApiHookLogParams("kernel32.dll", "QueueUserAPC", [ParamLogCtrl(4, "cbk", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "CreateMailslotW", [ParamLogCtrl(4, "name", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "SetSystemPowerState", [ParamLogCtrl(4, "is_suspend", V_PARAM_LOG_INT), ParamLogCtrl(8, "is_force", V_PARAM_LOG_INT)]),
    ApiHookLogParams("kernel32.dll", "SetSystemTime"),
    ApiHookLogParams("kernel32.dll", "SetSystemTimeAdjustment"),
    ApiHookCustom("kernel32.dll", "GetModuleHandleW", handler=handler_GetModuleHandleW, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "GetModuleHandleExW", handler=handler_GetModuleHandleExW, cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "DisableThreadLibraryCalls"),
    ApiHookLogParams("kernel32.dll", "FileTimeToSystemTime"),
    ApiHookLogParams("kernel32.dll", "SystemTimeToFileTime"),
    ApiHookLogParams("kernel32.dll", "SetProcessDEPPolicy"),

    ApiHookLogParams("kernel32.dll", "CreateIoCompletionPort"),
    ApiHookLogParams("kernel32.dll", "BindIoCompletionCallback"),
    ApiHookLogParams("kernel32.dll", "PostQueuedCompletionStatus"),
    ApiHookLogParams("kernel32.dll", "GetQueuedCompletionStatus"),

    ApiHookCustom("kernel32.dll", "IsProcessorFeaturePresent", handler=handler_IsProcessorFeaturePresent),
    ApiHookLogParams("kernel32.dll", "CreateHardLinkW", [ParamLogCtrl(4, "file_new", V_PARAM_LOG_PUSTR), ParamLogCtrl(8, "old_file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "GetLogicalProcessorInformation"),
    ApiHookLogParams("kernel32.dll", "GetNativeSystemInfo"),
]

func_other_kernel32_2 = [
    ApiHookCustom("kernel32.dll", "WaitForSingleObjectEx", handler=handler_WaitForSingleObjectEx, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "WaitForMultipleObjectsEx", handler=handler_WaitForMultipleObjectsEx, cstk_filter_depth=2),
    ApiHookLogParams("kernel32.dll", "CreateEventW", [ParamLogCtrl(0x10, "evt", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),

    # cause sample D0B78005C40EFC219CC1299A57B85C03 EXCEPTION
    ApiHookLogParams("kernel32.dll", "RaiseException"),
]

func_other_mpr = [
    ApiHookLogParams("mpr.dll", "WNetUseConnectionW", [ParamLogCtrl(0xC, "pwd", V_PARAM_LOG_PUSTR), ParamLogCtrl(0x10, "userid", V_PARAM_LOG_PUSTR)], cstk_filter_depth=3),
]

func_other_psapi = [
    ApiHookCustom("psapi.dll", "GetModuleFileNameExW", handler=handler_GetModuleFileNameExW, cstk_filter_depth=2),
    ApiHookCustom("psapi.dll", "GetProcessImageFileNameA", handler=handler_GetProcessImageFileNameA),
    ApiHookCustom("psapi.dll", "GetProcessImageFileNameW", handler=handler_GetProcessImageFileNameW),
]

func_other_msvcrt = [
    ApiHookCustom("msvcrt.dll", "_access", handler=handler_access),
]

func_other_msi = [
    ApiHookLogParams("msi.dll", "MsiViewFetch"),
]

func_other_shell32 = [
    ApiHookCustom("shell32.dll", "ShellExecuteExW", handler=handler_ShellExecuteExW, cstk_filter_depth=3),
]

func_other_shell32_1 = [
    ApiHookCustom("shell32.dll", "SHGetFolderPathW", handler=handler_SHGetFolderPathW, cstk_filter_depth=3),
]

func_other_advapi32 = [
    ApiHookLogParams("advapi32.dll", "OpenProcessToken"),
    ApiHookLogParams("advapi32.dll", "EncryptFileW", [ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
    ApiHookLogParams("advapi32.dll", "DecryptFileW", [ParamLogCtrl(4, "file", V_PARAM_LOG_PUSTR)], cstk_filter_depth=2),
]

func_other_ntdll = [
    ApiHookCustom("ntdll.dll", "ZwDelayExecution", handler=handler_ZwDelayExecution),
    # ApiHookCustom("ntdll.dll", "NtQueryInformationProcess", handler=handler_NtQueryInformationProcess),
    # ApiHookCustom("ntdll.dll", "NtQueryInformationThread", handler=handler_NtQueryInformationThread),
    ApiHookCustom("ntdll.dll", "NtSetInformationProcess", handler=handler_NtSetInformationProcess),
]

func_all_solid_dict = {
    "reg_advapi32": func_reg_advapi32,
    "sock_ws2_32": func_sock_ws2_32,
    "internet_wininet": func_internet_wininet,
    "internet_winhttp": func_internet_winhttp,
    "internet_urlmon": func_internet_urlmon,
    "proc_kernel32": func_proc_kernel32,
    "file_kernel32": func_file_kernel32,
    "svc_advapi32": func_svc_advapi32,
    "crypto_advapi32": func_crypto_advapi32,
    "mutex_kernel32": func_mutex_kernel32,
    "other_shell32": func_other_shell32,
    "priviledge_advapi32": func_priviledge_advapi32,
    "res_kernel32": func_res_kernel32,
    "other_kernel32": func_other_kernel32,
    "com_ole32": func_com_ole32,
    "mm_kernel32": func_mm_kernel32,
    "win_user32": func_win_user32,
}

func_all_unsolid_dict = {
    "internet_rasapi32": func_internet_rasapi32,
    "reg_advapi32_f": func_reg_advapi32_fragile,
    "dns_dnsapi": func_dns_dnsapi,
    "sock_ws2_32_WSA": func_sock_ws2_32_WSA,
    "internet_wininet_1": func_internet_wininet_1,
    "proc_kernel32_1": func_proc_kernel32_1,
    "proc_kernel32_2": func_proc_kernel32_2,
    "file_kernel32_1": func_file_kernel32_1,
    "file_shlwapi": func_file_shlwapi,
    "crypto_advapi32_1": func_crypto_advapi32_1,
    "str_shlwapi": func_str_shlwapi,
    "other_msvcrt": func_other_msvcrt,
    "other_msi": func_other_msi,
    "other_shell32_1": func_other_shell32_1,
    "other_advapi32": func_other_advapi32,
    "other_ntdll": func_other_ntdll,
    "evtlog_advapi32": func_evtlog_advapi32,
    "res_kernel32_1": func_res_kernel32_1,
    "pipe_kernel32": func_pipe_kernel32,
    "pipe_kernel32_1": func_pipe_kernel32_1,
    "other_mpr": func_other_mpr,
    "other_psapi": func_other_psapi,
    "dotnet_mscoree": func_dotnet_mscoree,
    "other_dbghelp": func_other_dbghelp,
    "profile_kernel32": func_profile_kernel32,
    "event_kernel32": func_event_kernel32,
    "timer_user32": func_timer_user32,
    "str_kernel32": func_str_kernel32,
    # "str_ntdll": func_str_ntdll,

    "other_kernel32_1": func_other_kernel32_1,
    "other_kernel32_2": func_other_kernel32_2,
    "com_ole32_1": func_com_ole32_1,
    "win_gdi32": func_win_gdi32,
    "win_user32_1": func_win_user32_1,
    "win_user32_2": func_win_user32_2,
    "hook_user32": func_hook_user32,
    "hook_user32_1": func_hook_user32_1,
    "atom_kernel32": func_atom_kernel32,
    "mm_ntdll": func_mm_ntdll,
    "environment_kernel32": func_environment_kernel32,
}

func_all = list(func_all_solid_dict.values() + func_all_unsolid_dict.values())

func_name_all = []


def _check_shall_we_pay_attention_to_func(func_name):
    """
        check if we shall add some api to out bp list
    """
    global func_name_all
    if len(func_name_all) == 0:
        global func_all
        for api_ctrl_item in func_all:
            func_name_all.append(api_ctrl_item.api_name)

    # manual add apis that we're not interested in.
    ignore_func_names = []

    return func_name not in func_name_all and func_name not in ignore_func_names


def _func_all_solid():
    """
        # solid and important apis that will not cause any trouble
    """
    ret = []
    ret = ret + func_reg_advapi32
    ret = ret + func_sock_ws2_32
    ret = ret + func_internet_wininet
    ret = ret + func_internet_winhttp
    ret = ret + func_internet_urlmon
    ret = ret + func_proc_kernel32
    ret = ret + func_file_kernel32
    ret = ret + func_svc_advapi32
    ret = ret + func_crypto_advapi32
    ret = ret + func_mutex_kernel32
    ret = ret + func_other_shell32
    ret = ret + func_priviledge_advapi32
    ret = ret + func_res_kernel32
    ret = ret + func_other_kernel32
    ret = ret + func_com_ole32
    ret = ret + func_mm_kernel32
    ret = ret + func_win_user32

    return ret


def _func_all_unsolid():
    """
        # solid and important apis that will not cause any trouble
    """
    ret = []

    # un-important apis
    ret = ret + func_other_msi
    ret = ret + func_hook_user32_1
    ret = ret + func_atom_kernel32
    ret = ret + func_pipe_kernel32_1
    ret = ret + func_other_psapi
    ret = ret + func_other_dbghelp
    ret = ret + func_other_kernel32_1
    ret = ret + func_environment_kernel32
    ret = ret + func_internet_wininet_1
    ret = ret + func_file_shlwapi
    ret = ret + func_file_kernel32_1
    ret = ret + func_crypto_advapi32_1
    ret = ret + func_win_user32_1
    ret = ret + func_win_gdi32
    ret = ret + func_evtlog_advapi32
    ret = ret + func_profile_kernel32
    ret = ret + func_res_kernel32_1
    ret = ret + func_other_shell32_1
    ret = ret + func_proc_kernel32_2
    ret = ret + func_internet_rasapi32

    # important apis that might cause trouble
    ret = ret + func_hook_user32
    ret = ret + func_sock_ws2_32_WSA
    ret = ret + func_pipe_kernel32
    ret = ret + func_other_mpr
    ret = ret + func_com_ole32_1
    ret = ret + func_dns_dnsapi
    ret = ret + func_str_shlwapi
    ret = ret + func_str_kernel32
    ret = ret + func_win_user32_2

    # un-important and might cause trouble apis
    ret = ret + func_other_advapi32
    ret = ret + func_other_msvcrt
    ret = ret + func_mm_ntdll
    ret = ret + func_event_kernel32
    ret = ret + func_timer_user32

    # important apis that very likely cause trouble
    ret = ret + func_other_ntdll
    ret = ret + func_dotnet_mscoree
    ret = ret + func_other_kernel32_2
    ret = ret + func_mm_kernel32_1
    ret = ret + func_proc_kernel32_1
    ret = ret + func_reg_advapi32_fragile

    # we don't need this
    # ret = ret + func_str_ntdll

    return ret

func_xx = [
    ApiHookCustom("kernel32.dll", "SleepEx", handler=handler_SleepEx, cstk_filter_depth=2),
    ApiHookCustom("kernel32.dll", "TerminateProcess", handler=handler_TerminateProcess),
    ApiHookCustom("kernel32.dll", "ExitProcess", handler=handler_ExitProcess),
]

func_test = [

]


def gather_apis():
    """
    """
    global v_tmp_gather_api_type_str
    assert v_tmp_gather_api_type_str is not None

    x_func = []

    if "s" in v_tmp_gather_api_type_str:

        # exclude solid cats
        global v_tmp_ignore_cat_names
        if v_tmp_ignore_cat_names is not None and len(v_tmp_ignore_cat_names) != 0:
            for (cat_name, cat_items) in func_all_solid_dict.items():
                if cat_name not in v_tmp_ignore_cat_names:
                    x_func = x_func + cat_items
        else:
            # for test, to find which api/cat is fucking crazy...
            x_func = _func_all_solid()

    if "u" in v_tmp_gather_api_type_str:
        # exclude solid cats
        global v_tmp_ignore_cat_names
        if v_tmp_ignore_cat_names is not None and len(v_tmp_ignore_cat_names) != 0:
            for (cat_name, cat_items) in func_all_unsolid_dict.items():
                if cat_name not in v_tmp_ignore_cat_names:
                    x_func = x_func + cat_items
        else:
            # for test, to find which api/cat is fucking crazy...
            x_func = x_func + _func_all_unsolid()

    if "x" in v_tmp_gather_api_type_str:
        x_func = x_func + func_xx

    if "t" in v_tmp_gather_api_type_str:
        x_func = func_test

    if "n" in v_tmp_gather_api_type_str:
        x_func = []

    # ---------------------------------------------------------------------------
    # exclude apis

    global v_tmp_ignore_api_names
    if len(v_tmp_ignore_api_names) != 0:
        _pt_log("ignore apis: %s" % str(v_tmp_ignore_api_names))

        i = 0
        while i < len(x_func):
            x_func_item = x_func[i]

            # _pt_log(">>> check ignore api name: %s" % x_func_item.api_name)

            if x_func_item.api_name in v_tmp_ignore_api_names:

                x_func.remove(x_func_item)
                # _pt_log(">>> remove ignore api: %s" % x_func_item.api_name)

            else:
                i = i + 1

    _pt_log(">>> apis to bp: %d" % len(x_func))

    # ---------------------------------------------------------------------------
    # add to v_tmp_

    global v_tmp_dll_apis
    assert v_tmp_dll_apis is None

    v_tmp_dll_apis = {}
    for func in x_func:
        if func.dll_name not in v_tmp_dll_apis:
            v_tmp_dll_apis[func.dll_name] = []
        v_tmp_dll_apis[func.dll_name].append(func)
        # _pt_log(">>> add api to dll-bp-list: %s" % func.api_name)


def gather_alloc_apis():
    """
        only gather alloc apis
    """
    # i know it's ugly...
    alloc_func = [
        ApiHookCustom("kernel32.dll", "VirtualAllocEx", handler=handler_VirtualAllocEx, cstk_filter_depth=2),
        # ApiHookLogParams("kernel32.dll", "TlsAlloc"),
        ApiHookCustom("ntdll.dll", "RtlAllocateHeap", handler=handler_RtlAllocateHeap, cstk_filter_depth=2),
        ApiHookCustom("ntdll.dll", "RtlReAllocateHeap", handler=handler_RtlReAllocateHeap, cstk_filter_depth=2),
    ]

    global v_tmp_dll_apis
    assert v_tmp_dll_apis is None

    v_tmp_dll_apis = {}
    for func in alloc_func:
        if func.dll_name not in v_tmp_dll_apis:
            v_tmp_dll_apis[func.dll_name] = []
        v_tmp_dll_apis[func.dll_name].append(func)
        # _pt_log(">>> add api to dll-bp-list: %s" % func.api_name)


# ---------------------------------------------------------------------------

def handler_all_api_proxy(dbg):
    """
        check call stack, proxy to it's own handlers if passed
    """
    eip = dbg.context.Eip

    # ---------------------------------------------------------------------------
    # time

    global v_tmp_is_pt_api_invoke_time
    if v_tmp_is_pt_api_invoke_time:
        start = datetime.datetime.now()

    # ---------------------------------------------------------------------------
    # bp hit count

    global v_tmp_bp_hit_count
    v_tmp_bp_hit_count = v_tmp_bp_hit_count + 1

    # ---------------------------------------------------------------------------
    # fixup

    global v_tmp_addr_to_api
    if eip not in v_tmp_addr_to_api:

        # for unknown reason(might be bug), this eip is (api_start-1), in that case, we fix it manually.

        eip = eip + 1
        if eip not in v_tmp_addr_to_api:
            _pt_log(">>> invalid eip/eip+1, which does not exist in v_tmp_addr_to_api:")
            _pt_log(">>>     eip: %s" % dbg.addr_resolve(eip - 1))

            dbg.bp_del(eip)
            return defines.DBG_CONTINUE
        else:
            _pt_log(">>> invalid eip, but valid eip+1: %s" % dbg.addr_resolve(eip))

    api_ctrl = v_tmp_addr_to_api[eip]

    # ---------------------------------------------------------------------------
    # last api

    global v_tmp_last_api_name
    v_tmp_last_api_name[dbg.dbg.dwThreadId] = api_ctrl_base.api_name

    # ---------------------------------------------------------------------------
    # api invoke count

    global v_tmp_api_invoke_summary
    if api_ctrl_base.api_name not in v_tmp_api_invoke_summary:
        v_tmp_api_invoke_summary[api_ctrl_base.api_name] = (0, 0, 1)
    else:
        ok_cnt = v_tmp_api_invoke_summary[api_ctrl_base.api_name][0]
        no_cnt = v_tmp_api_invoke_summary[api_ctrl_base.api_name][1]
        all_cnt = v_tmp_api_invoke_summary[api_ctrl_base.api_name][2]
        v_tmp_api_invoke_summary[api_ctrl_base.api_name] = (ok_cnt, no_cnt, all_cnt + 1)

    # ---------------------------------------------------------------------------

    # always pt api invoke, for test
    # dft=False
    global v_tmp_is_pt_all_api_invoke_always
    if v_tmp_is_pt_all_api_invoke_always:
        _pt_log("proxy api invoke: %s" % api_ctrl)
    else:
        # only pt api invoke, for test
        # dft=False
        global v_tmp_is_pt_all_api_invoke_only
        if v_tmp_is_pt_all_api_invoke_only:
            _pt_log("proxy api invoke: %s" % api_ctrl)
            return defines.DBG_CONTINUE

    global v_tmp_is_pt_all_api_stacks_always
    if v_tmp_is_pt_all_api_stacks_always:
        pt_resolved_call_stacks_default(dbg, is_fix_api_start=True)

    # ---------------------------------------------------------------------------
    # filter call stack

    global v_tmp_is_check_call_stack
    if v_tmp_is_check_call_stack:

        is_ok = False
        cstks_tmp = dbg.get_call_stacks_default(depth=api_ctrl_base.cstk_filter_depth, is_fix_api_start=True)
        assert cstks_tmp is not None

        # since we fixed api start, retn stack depth is 1 larger than our expected, so we remove the tail.
        # but for unknown reason, this is incorrect.
        # we only do this for "GetProcAddress", alought this is quite ugly.
        is_ignore = False
        ignore_from_to_pairs = [
            # (0000AE30)kernel32.dll._GetProcAddress@8+00000000 | (0000737E)ws2_32.dll.?CheckForHookersOrChainers@@YGHXZ+00000022
            # (0000737E)ws2_32.dll.?CheckForHookersOrChainers@@YGHXZ+00000022 | (00007024)1111.exe.00407024
            ("GetProcAddress", "CheckForHookersOrChainers"),
            # (000024B7)kernel32.dll._ReleaseMutex@4+00000000 | (0005AD9F)kernel32.dll._OutputDebugStringA@4+00000123
            # (0005AD9F)kernel32.dll._OutputDebugStringA@4+00000123 | (00062664)1111.exe.00462664
            ("ReleaseMutex", "OutputDebugStringA"),
            # (00012A99)kernel32.dll._RaiseException@16+00000000 | (0005ACD0)kernel32.dll._OutputDebugStringA@4+00000054
            # (0005ACD0)kernel32.dll._OutputDebugStringA@4+00000054 | (00062664)1111.exe.00462664
            ("RaiseException", "OutputDebugStringA"),
        ]
        cstks_tmp_resolved = None
        for from_to_pair in ignore_from_to_pairs:
            if api_ctrl_base.api_name == from_to_pair[0] and len(cstks_tmp) >= 2:
                # we need to resolve it, because we need to check stack.to_func_name
                cstks_tmp_resolved = cstks_tmp_resolved is None and resolve_call_stacks(cstks_tmp) or cstks_tmp_resolved
                if cstks_tmp_resolved[0].to_func_name is not None and from_to_pair[1] in cstks_tmp_resolved[0].to_func_name:
                    is_ignore = True
                    break

        if not is_ignore:
            # since we don't bp at these special apis which will result in unknown results, this filter is not needed anymore.
            # if pass_special_check(api_ctrl, cstks_tmp):

            if len(cstks_tmp) != 0:

                debugee_name = util.debugee_name()
                for cstk_tmp in cstks_tmp:
                    if (debugee_name == cstk_tmp.from_md_name or debugee_name == cstk_tmp.to_md_name):
                        # we give it a "yes": from debugee
                        is_ok = True
                        break

                    if (cstk_tmp.from_md_name is None or cstk_tmp.to_md_name is None) and cstk_tmp.to_addr != 0:
                        # we give it a "yes": from heap or stack
                        is_ok = True
                        break

                if not is_ok:
                    # above says "no"
                    pass

            else:
                # we give no stack a "yes"
                is_ok = True
            # else:
            #     # we give it a "no"
            #     pass

    else:
        is_ok = True

    # ---------------------------------------------------------------------------
    # api invoke count
    ok_cnt = v_tmp_api_invoke_summary[api_ctrl_base.api_name][0]
    no_cnt = v_tmp_api_invoke_summary[api_ctrl_base.api_name][1]
    all_cnt = v_tmp_api_invoke_summary[api_ctrl_base.api_name][2]
    if is_ok:
        v_tmp_api_invoke_summary[api_ctrl_base.api_name] = (ok_cnt + 1, no_cnt, all_cnt)
    else:
        v_tmp_api_invoke_summary[api_ctrl_base.api_name] = (ok_cnt, no_cnt + 1, all_cnt)

    # ---------------------------------------------------------------------------
    # main

    if is_ok:

        param_dict = {}
        if isinstance(api_ctrl, ApiHookLogParams):

            # not-custom, might only log params
            if api_ctrl_base.param_log_ctrl_list is None or len(api_ctrl_base.param_log_ctrl_list) == 0:

                # no params needed
                _xrk_api_invoke_detail(dbg, api_ctrl_base.api_name)

            else:
                # get params
                for ParamLogCtrl in api_ctrl_base.param_log_ctrl_list:

                    # _pt_log(">>> get log %s - %s" % (api_ctrl_base.api_name, ParamLogCtrl))

                    param_dict[ParamLogCtrl.log_name] = ParamLogCtrl.get_log(dbg)
                _xrk_api_invoke_detail(dbg, api_ctrl_base.api_name, param_dict)

        else:
            # proxy to custom handler
            param_dict = api_ctrl_base.handler(dbg)
            # looking for bugs....
            if param_dict is None:
                _pt_log(">>> custom handler of api %s retn None" % api_ctrl_base.api_name)
                param_dict = {}

        # maybe del bp if api invoke too frequently
        global v_tmp_api_invoke_cnt_dict_runtime
        if api_ctrl_base.api_name not in v_tmp_api_invoke_cnt_dict_runtime:
            v_tmp_api_invoke_cnt_dict_runtime[api_ctrl_base.api_name] = 1
        else:
            v_tmp_api_invoke_cnt_dict_runtime[api_ctrl_base.api_name] = v_tmp_api_invoke_cnt_dict_runtime[api_ctrl_base.api_name] + 1
            # may del bp
            if api_ctrl_base.max_invoke_cnt_runtime is not None and api_ctrl_base.max_invoke_cnt_runtime < v_tmp_api_invoke_cnt_dict_runtime[api_ctrl_base.api_name]:
                dbg.bp_del(dbg.context.Eip)
                # _pt_log(">>> api invoke reach max limit, remove bp: %d - %s" % (api_ctrl_base.max_invoke_cnt_runtime, api_ctrl_base.api_name))

        # pt stacks
        global v_tmp_is_pt_filtered_api_stacks
        if v_tmp_is_pt_filtered_api_stacks:
            pt_resolved_call_stacks_default(dbg, is_fix_api_start=True)

        # add to api summary for output
        params_str = ""
        if len(param_dict) != 0:
            for (param_str, value_str) in param_dict.items():
                params_str += "(%s:%s)" % (param_str, value_str)
        output.add_api_hit_record(api_ctrl_base.api_name, get_resolved_call_stacks_default(dbg, is_fix_api_start=True), params_str)

    else:
        # _pt_log("no - %s" % api_ctrl_base.api_name)
        pass

    # ---------------------------------------------------------------------------

    if v_tmp_is_pt_api_invoke_time:
        end = datetime.datetime.now()
        _pt_log("api invoke: %s, time: %.8d msecs" % (api_ctrl_base.api_name, (end - start).microseconds / 1000))

    return defines.DBG_CONTINUE


def dbg_set_api_bp(dbg, api_ctrl):
    """
        set api bp(dll shall be already installed)
    """
    addr = dbg.func_resolve(api_ctrl_base.dll_name, api_ctrl_base.api_name)
    if addr is not None and addr != 0:

        global v_tmp_is_pt_when_set_api_bp
        if v_tmp_is_pt_when_set_api_bp:
            _pt_log("bp set for api: %s - %.8X" % (api_ctrl, addr))

        try:
            dbg.bp_set(addr, handler=handler_all_api_proxy)
        except:
            dbg._warn("set api bp fail: %s - %.8X" % (api_ctrl, addr))

        # add to xxx
        global v_tmp_addr_to_api
        assert addr not in v_tmp_addr_to_api
        v_tmp_addr_to_api[addr] = api_ctrl

    else:
        _pt_log("resolve addr fail: %s" % api_ctrl)


# ---------------------------------------------------------------------------
# things to do when new dll loaded
# !+ debugee is already loaded +!

def install_api_hooks(dbg, dll_api_hooks):
    """
        check if install api hooks
    """
    # _pt_log("remain system dlls to install api hook: %d" % (len(dll_api_hooks)))

    new_sys_dll = dbg.system_dlls[-1]
    dll_name = new_sys_dll.name.lower()

    for (dll_name, api_ctrl_list) in dll_api_hooks.items():
        if dbg.check_has_system_dll(dll_name):
            for api_ctrl in api_ctrl_list:
                dbg_set_api_bp(dbg, api_ctrl)
            del dll_api_hooks[dll_name]


def check_install_api_hooks(dbg):
    """
        check if any apis hooks remain to install
    """
    global v_tmp_dll_apis
    if len(v_tmp_dll_apis) != 0:
        install_api_hooks(dbg, v_tmp_dll_apis)


# ---------------------------------------------------------------------------
# callback

def callback_process_exit_pt_exit_call_stacks(dbg):
    """
        print exit call stacks for each thread
    """
    global v_tmp_is_pt_process_exit_call_stacks
    if v_tmp_is_pt_process_exit_call_stacks:
        _pt_log("-" * 100)
        _pt_log(">>> exit call stacks of all threads:")
        pt_resolved_call_stacks_all(dbg, depth=None, is_fix_api_start=True)


def callback_process_exit_pt_api_details_summary(dbg):
    """
        print call details summary
    """
    global v_tmp_is_pt_process_exit_api_summary
    if v_tmp_is_pt_process_exit_api_summary:
        _pt_log("-" * 100)
        _pt_log(">>> api call summary:")
        output.pt_api_summary()


def callback_process_exit_pt_api_invoke_summary(dbg):
    """
        print api invoke summary
    """
    global v_tmp_api_invoke_summary
    if len(v_tmp_api_invoke_summary) != 0:

        _pt_log("-" * 100)

        api_to_cnt_dict = {}
        for (api_name, x_cnt) in v_tmp_api_invoke_summary.items():
            api_to_cnt_dict[api_name] = x_cnt[2]
        sorted_api_names = sorted(api_to_cnt_dict, key=api_to_cnt_dict.__getitem__)

        api_str_over_fuck_max = ""
        api_str_not_mine_but_over_fuck_max = ""
        api_str_not_mine_not_over_fuck_max = ""
        api_str_lit_mine_but_over_fuck_max = ""
        api_str_lit_mine_not_over_fuck_max = ""

        bp_hit_all_cnt = 0
        bp_hit_ok_cnt = 0

        fuck_max = 50

        _pt_log(">>> %d api invoke count: " % len(sorted_api_names))
        _pt_log("%-40s - ok   - no   - all" % (" "))
        for i in range(len(sorted_api_names)):

            api_name = sorted_api_names[i]
            ok_cnt = v_tmp_api_invoke_summary[api_name][0]
            no_cnt = v_tmp_api_invoke_summary[api_name][1]
            all_cnt = v_tmp_api_invoke_summary[api_name][2]

            _pt_log("%-40s - %.4d - %.4d - %.4d - %.4f" % (api_name, ok_cnt, no_cnt, all_cnt, ok_cnt / float(all_cnt)))

            api_name_str = "\"%s\", " % api_name
            # api_name_str_perct = "\"%s\"(%.2f), " % (api_name, ok_cnt / float(all_cnt))

            # sum apis invoke too much
            if all_cnt >= fuck_max:
                api_str_over_fuck_max = api_str_over_fuck_max + api_name_str

            # sum apis not/little is mine
            if ok_cnt == 0:
                # not mine
                if all_cnt >= fuck_max:
                    api_str_not_mine_but_over_fuck_max = api_str_not_mine_but_over_fuck_max + api_name_str
                else:
                    api_str_not_mine_not_over_fuck_max = api_str_not_mine_not_over_fuck_max + api_name_str

            else:
                if ok_cnt / float(all_cnt) < 0.05:
                    # little is mine
                    if all_cnt >= fuck_max:
                        api_str_lit_mine_but_over_fuck_max = api_str_lit_mine_but_over_fuck_max + api_name_str  # api_name_str_perct
                    else:
                        api_str_lit_mine_not_over_fuck_max = api_str_lit_mine_not_over_fuck_max + api_name_str  # api_name_str_perct
                else:
                    # most is mine. we don't need this output.
                    pass

            # sum hit count
            bp_hit_all_cnt = bp_hit_all_cnt + all_cnt
            bp_hit_ok_cnt = bp_hit_ok_cnt + ok_cnt

        _pt_log("-" * 100)

        if len(api_str_over_fuck_max) != 0:
            _pt_log(">>> invoke cnt > %d(all):" % fuck_max)
            _pt_log("    %s" % api_str_over_fuck_max)
            _pt_log("")
        if len(api_str_not_mine_but_over_fuck_max) != 0:
            _pt_log(">>> invoke cnt > %d(but none is mine):" % fuck_max)
            _pt_log("    %s" % api_str_not_mine_but_over_fuck_max)
            _pt_log("")
        # if len(api_str_not_mine_not_over_fuck_max) != 0:
        #     _pt_log(">>> invoke cnt < %d(but none is mine):" % fuck_max)
        #     _pt_log("    %s" % api_str_not_mine_not_over_fuck_max)
        #     _pt_log("")
        if len(api_str_lit_mine_but_over_fuck_max) != 0:
            _pt_log(">>> invoke cnt > %d(but litt is mine):" % fuck_max)
            _pt_log("    %s" % api_str_lit_mine_but_over_fuck_max)
            _pt_log("")
        # if len(api_str_lit_mine_not_over_fuck_max) != 0:
        #     _pt_log(">>> invoke cnt < %d(but litt is mine):" % fuck_max)
        #     _pt_log("    %s" % api_str_lit_mine_not_over_fuck_max)
        #     _pt_log("")

        _pt_log("-" * 100)
        _pt_log(">>> apis hit percentage: %d/%d(%.4f)" % (bp_hit_ok_cnt, bp_hit_all_cnt, bp_hit_ok_cnt / float(bp_hit_all_cnt)))


def callback_process_exit_pt_last_api(dbg):
    """
        print last api of each thread and whether process terminate normally or not.
    """
    _pt_log("-" * 100)

    global v_tmp_last_api_name
    if len(v_tmp_last_api_name) != 0:
        for (tid, api) in v_tmp_last_api_name.items():
            _pt_log(">>> lastest api: %.8X - %s" % (tid, api))
    else:
        _pt_log(">>> no api invoked")

    global v_tmp_is_normal_termination
    if not v_tmp_is_normal_termination:
        tid_to_stacks_dict = get_resolved_call_stacks_all(dbg, depth=None, is_fix_api_start=True)
        for (tid, stacks_list) in tid_to_stacks_dict.items():
            for stack in stacks_list:
                if (stack.from_func_name is not None and "ExitProcess" in stack.from_func_name) or (stack.to_func_name is not None and "ExitProcess" in stack.to_func_name):
                    v_tmp_is_normal_termination = True
                    break
            if v_tmp_is_normal_termination:
                break

    if v_tmp_is_normal_termination:
        _pt_log(">>> [[[process terminate normally]]]")
    else:
        _pt_log(">>> [[[unexpected process termination]]]")


def callback_process_exit_pt_bp_hit_count(dbg):
    """
        print bp hit count
    """
    global v_tmp_bp_hit_count
    if v_tmp_bp_hit_count != 0:

        # do this in callback_process_exit_pt_api_invoke_summary()
        # _pt_log(">>> all bp hit count: %d" % v_tmp_bp_hit_count)
        pass


def callback_process_exit_pt_file_reg_proc_summary(dbg):
    """
        print file/reg/proc summary
    """
    global v_tmp_file_name_summary
    if len(v_tmp_file_name_summary) != 0:
        _pt_log("-" * 100)
        _pt_log(">>> file summary: %d" % len(v_tmp_file_name_summary))
        for file in v_tmp_file_name_summary:
            _pt_log(file)

    global v_tmp_reg_name_summary
    if len(v_tmp_reg_name_summary) != 0:
        _pt_log("-" * 100)
        _pt_log(">>> reg summary: %d" % len(v_tmp_reg_name_summary))
        for reg in v_tmp_reg_name_summary:
            _pt_log(reg)

    global v_tmp_proc_name_summary
    if len(v_tmp_proc_name_summary) != 0:
        _pt_log("-" * 100)
        _pt_log(">>> proc summary: %d" % len(v_tmp_proc_name_summary))
        for proc in v_tmp_proc_name_summary:
            _pt_log(proc)


def callback_process_exit_pt_manual_resolved_funcs(dbg):
    """
        pt manual resolved apis
    """
    global v_tmp_is_pt_manual_resolved_funcs
    if v_tmp_is_pt_manual_resolved_funcs:
        global v_tmp_manual_resolved_funcs
        if len(v_tmp_manual_resolved_funcs) != 0:
            _pt_log("-" * 100)
            _pt_log(">>> debugee manual resolved funcs:")
            for func_name in v_tmp_manual_resolved_funcs:
                if _check_shall_we_pay_attention_to_func(func_name):
                    _pt_log("%s" % func_name)


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
