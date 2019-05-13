# -*- coding: utf-8 -*-

"""
msdn thing
"""

import os
import sys
import inspect
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # _util

from util import *

# 为了在磁盘上找到文件
file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))
# UTF-8：0001无法转换为数字
# ANSI : 中文部分要decode为"GB2312"
file_code_error = os.path.join(file_dir, "msdn", "code_error.txt")
file_code_exception = os.path.join(file_dir, "msdn", "code_exception.txt")
file_code_win_msg = os.path.join(file_dir, "msdn", "code_win_msg.txt")


# ---------------------------------------------------------------------------

v_tmp_code_error_dict = None
v_tmp_code_exception_dict = None
v_tmp_code_win_msg_dict = None

# ---------------------------------------------------------------------------


def load_code_error():
    """
    """
    global v_tmp_code_error_dict
    assert v_tmp_code_error_dict is None
    v_tmp_code_error_dict = {}

    if os.path.exists(file_code_error):
        try:
            file = open(file_code_error, "r")
        except:
            print ">>> open file exception: %s" % file_code_error
        else:
            for line in file:

                splits = line.split(" ")
                assert len(splits) == 2

                code = int(splits[0])  # 这是10进制的
                msg = splits[1].strip("\n").decode("GB2312")  # 这是中文

                v_tmp_code_error_dict[code] = msg

            file.close()


def load_code_exception():
    """
    """
    global v_tmp_code_exception_dict
    assert v_tmp_code_exception_dict is None
    v_tmp_code_exception_dict = {}

    if os.path.exists(file_code_exception):
        try:
            file = open(file_code_exception, "r")
        except:
            print ">>> open file exception: %s" % file_code_exception
        else:
            for line in file:

                splits = line.split(" ")
                assert len(splits) == 2

                code = int(splits[0], 16)  # 这是16进制的
                msg = splits[1].strip("\n")  # 英文

                v_tmp_code_exception_dict[code] = msg

            file.close()


def load_code_win_msg():
    """
    """
    global v_tmp_code_win_msg_dict
    assert v_tmp_code_win_msg_dict is None
    v_tmp_code_win_msg_dict = {}

    if os.path.exists(file_code_win_msg):
        try:
            file = open(file_code_win_msg, "r")
        except:
            print ">>> open file exception: %s" % file_code_win_msg
        else:
            for line in file:

                splits = line.split(" ")
                assert len(splits) == 3

                code = int(splits[0], 16)  # 这是16进制的
                msg = splits[1]  # 英文
                msgx = splits[2].strip("\n")  # 中文

                v_tmp_code_win_msg_dict[code] = "%s-%s" % (msg, msgx.decode("GB2312"))

            file.close()


# ---------------------------------------------------------------------------

def _resolve_code_error(code):
    """
    @param: code : int : error code
    @return: string :
    """
    if code >= 0x4000:
        return "超过范围的错误码: %.8X" % code

    global v_tmp_code_error_dict
    if v_tmp_code_error_dict is None:
        load_code_error()

    if code not in v_tmp_code_error_dict:
        return "无法识别的错误码: %.8X" % code

    return v_tmp_code_error_dict[code]


def resolve_code_error(code):
    return to_str(_resolve_code_error(code))


def _resolve_code_exception(code):
    """
    @param: code : int : exception code
    @return: string :
    """
    global v_tmp_code_exception_dict
    if v_tmp_code_exception_dict is None:
        load_code_exception()

    if code not in v_tmp_code_exception_dict:
        return "无法识别的异常代码: %.8X" % code

    return v_tmp_code_exception_dict[code]


def resolve_code_exception(code):
    return to_str(_resolve_code_exception(code))


def _resolve_code_win_msg(code):
    """
        @param: code : int : win msg code
        @return: string :
    """
    if code <= 0x0400:

        global v_tmp_code_win_msg_dict
        if v_tmp_code_win_msg_dict is None:
            load_code_win_msg()
        if code not in v_tmp_code_win_msg_dict:
            return "无法识别的消息代码: %.8X" % code

        return v_tmp_code_win_msg_dict[code]

    if code <= 0x8000:
        return "用户自定义消息"
    if code <= 0xC000:
        return "应用程序自定义消息"
    if code <= 0xFFFF:
        return "应用程序字符串消息"
    return "系统应用保留"


def resolve_code_win_msg(code):
    return to_str(_resolve_code_win_msg(code))


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
