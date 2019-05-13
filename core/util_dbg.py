# -*- coding: utf-8 -*-

"""
与 dbg 相关的辅助函数
"""

from __future__ import print_function
# # from __future__ import unicode_literals

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # repo-pydbg

from _util.util import *
from _core import dbg


# ---------------------------------------------------------------------------


def log(file, msg):
    if dbg:
        dbg.info(file, msg)
    else:
        print("[NO-DBG-INFO] - %s" % msg)


def warn(file, msg):
    if dbg:
        dbg.warn(file, msg)
    else:
        print("[NO-DBG-WARN] - %s" % msg)


def error(file, msg):
    if dbg:
        dbg.error(file, msg)
    else:
        print("[NO-DBG_ERROR] - %s" % msg)


# ---------------------------------------------------------------------------


def get_reg_data(dbg, type_, pdata, data_size=0):
    """根据注册表的类型, 读取注册表的值"""
    import _winreg
    if type_ == _winreg.REG_BINARY:
        assert data_size != 0
        return "REG_BINARY", "xxx"
    elif type_ == _winreg.REG_DWORD:
        return "REG_DWORD", "%d" % read_int32(dbg, pdata)
    elif type_ == _winreg.REG_DWORD_LITTLE_ENDIAN:
        return "REG_DWORD_LITTLE_ENDIAN", "NONE"
    elif type_ == _winreg.REG_DWORD_BIG_ENDIAN:
        return "REG_DWORD_BIG_ENDIAN", "NONE"
    elif type_ == _winreg.REG_EXPAND_SZ:
        return "REG_EXPAND_SZ", read_ascii_string(dbg, pdata)
    elif type_ == _winreg.REG_LINK:
        return "REG_LINK", "NONE"
    elif type_ == _winreg.REG_MULTI_SZ:
        return "REG_MULTI_SZ", read_ascii_string(dbg, pdata)
    elif type_ == _winreg.REG_NONE:
        return "REG_NONE", "NONE"
    elif type_ == _winreg.REG_SZ:
        return "REG_SZ", read_ascii_string(dbg, pdata)
    else:
        return "", ""


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
    msg = read_int32(dbg, p_msg + 4)

    return msg


# ---------------------------------------------------------------------------


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
