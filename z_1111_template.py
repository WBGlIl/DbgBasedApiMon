# -*- coding: utf-8 -*-

"""
debugee hooks
"""

import log
import defines


# ---------------------------------------------------------------------------
# target file that copy sample to, or fake ret path

z_tmp_target_file = r"".lower()
z_tmp_target_cmd_line = None
z_tmp_fake_module_file_name = None


# ---------------------------------------------------------------------------
# is hide debugger
z_tmp_is_hide_debugger = True


# ---------------------------------------------------------------------------
# is install hooks only when debugee entry point is hit.
z_tmp_is_bp_apis_only_when_debugee_ep_hit = True


# ---------------------------------------------------------------------------
# sock connect addr
z_tmp_new_sock_connect_ip = None  # in this format: "\xC0\xA8\x01\x0A", which means: 192.168.1.10
z_tmp_new_sock_connect_port = None


# ---------------------------------------------------------------------------
# http connect addr
z_tmp_new_http_connect_addr = None  # in this format: "192.168.1.10"


# ---------------------------------------------------------------------------
# log

def _pt_log(line):
    """
        proxy to log.pt_log()
    """
    log.pt_log(line)


# ---------------------------------------------------------------------------
# str decrypt

z_tmp_decrypted_str_dict = {}


def handler_str_decrypted(dbg):
    """
        add decrypted str dict to global var
    """
    """
    addr = dbg.read_stack_int32(4)
    str_ = dbg.read_ascii_string(addr)

    print ">>> decrypted: %.8X --> %s" % (addr, str_)

    global z_tmp_decrypted_str_dict

    # if each string is decrypt only once, then we can make this assert
    # assert addr not in z_tmp_decrypted_str_dict
    # z_tmp_decrypted_str_dict[addr] = str_

    # or, we need to check
    if addr not in z_tmp_decrypted_str_dict:
        z_tmp_decrypted_str_dict[addr] = str_
    """
    return defines.DBG_CONTINUE


def pt_str_decrypted():
    """
        print decrypted string
    """
    global z_tmp_decrypted_str_dict
    _pt_log(">>> string decrypted:")
    for (addr, str_) in z_tmp_decrypted_str_dict.items():
        _pt_log("0x%.8X: \"%s\"," % (addr, str_))


# ---------------------------------------------------------------------------
# hooks

"""

def handler_1(dbg):
    print ">>> 11111111111111111111111"
    return defines.DBG_CONTINUE


def handler_2(dbg):
    print ">>> 22222222222222222222222"
    return defines.DBG_CONTINUE


def handler_3(dbg):
    print ">>> 33333333333333333333333"
    return defines.DBG_CONTINUE
"""

z_tmp_debugee_hooks = {
    # 0x004079E9: handler_1,
    # 0x004079EA: handler_2,
    # 0x004079F0: handler_3,
}


# ---------------------------------------------------------------------------
# ignore api/cat names
z_tmp_ignore_cat_names = [

]
z_tmp_ignore_api_names = [

]


# ---------------------------------------------------------------------------
# nop ranges: [(start, end), (start, end), ...]
z_tmp_debugee_nop_ranges = [

]

# ---------------------------------------------------------------------------
# exit callback


def callback_process_exit(dbg):
    """
        process exit
    """
    # pt_str_decrypted()
    pass


z_tmp_debugee_exit_cbk = None


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
