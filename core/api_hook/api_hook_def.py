# -*- coding: utf-8 -*-

"""
api_hook 的多种类

1. x64dbgpyx 中需要有对应的类定义
2. 这里没有什么设置断点类型之类的. core 只提供 hook 定义, 至于要不要用、怎么用, 由调试器自己处理

"""

from __future__ import print_function
# from __future__ import unicode_literals

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))                    # core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))   # repo-pydbg

from _util.util import *
from util_dbg import *

# ---------------------------------------------------------------------------
# 日志


def _log(msg):
    log(__file__, msg)


def _warn(msg):
    warn(__file__, msg)


def _error(msg):
    error(__file__, msg)


# ---------------------------------------------------------------------------
# 类定义


V_PARAM_LOG_BYTE = 1
V_PARAM_LOG_WORD = 2
V_PARAM_LOG_INT = 3
V_PARAM_LOG_PBYTE = 4
V_PARAM_LOG_PWORD = 5
V_PARAM_LOG_PINT = 6
V_PARAM_LOG_ASTR = 7
V_PARAM_LOG_USTR = 8
V_PARAM_LOG_PASTR = 9
V_PARAM_LOG_PUSTR = 10
V_PARAM_LOG_PPASTR = 11
V_PARAM_LOG_PPUSTR = 12


V_WEIGHT_IGNORE = 1
V_WEIGHT_LOW = 3
V_WEIGHT_MIDDLE = 5
V_WEIGHT_HIGH = 7
V_WEIGHT_CRITICAL = 9


class ParamLogCtrl(object):
    """记录 api 参数的类型"""

    def __init__(self, esp_offset, log_name, log_type):
        """
            @param: esp_offset : int    : 参数相对 ESP 的偏移
            @param: log_name   : string : 记录的参数名称
            @param: log_type   : int    : 参数的类型: [V_PARAM_LOG_BYTE, ...]
        """
        self.esp_offset = esp_offset
        self.log_name = log_name
        self.log_type = log_type

    def get_log(self, dbg):
        """
            根据参数类型读取参数的值, 并返回字符串表示

            @return: string : value_str
        """
        value = ""
        if self.log_type == V_PARAM_LOG_BYTE:
            value = "%d" % read_stack_int8(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_WORD:
            value = "%.4X" % read_stack_int16(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_INT:
            value = "%.8X" % read_stack_int32(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_PBYTE:
            value = "%d" % read_stack_p_int8(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_PWORD:
            value = "%.4X" % read_stack_p_int16(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_PINT:
            value = "%.8X" % read_stack_p_int32(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_ASTR:
            value = read_stack_ascii_string(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_USTR:
            value = read_stack_unicode_string(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_PASTR:
            value = read_stack_p_ascii_string(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_PUSTR:
            value = read_stack_p_unicode_string(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_PPASTR:
            value = read_stack_pp_ascii_string(dbg, self.esp_offset)

        elif self.log_type == V_PARAM_LOG_PPUSTR:
            value = read_stack_pp_unicode_string(dbg, self.esp_offset)

        else:
            assert False

        return str(value)

    def __str__(self):
        ret = "%s(%.8X)" % (self.log_name, self.esp_offset)
        if self.log_type == V_PARAM_LOG_BYTE:
            ret = ret + "BYTE"
        elif self.log_type == V_PARAM_LOG_WORD:
            ret = ret + "WORD"
        elif self.log_type == V_PARAM_LOG_INT:
            ret = ret + "INT"
        elif self.log_type == V_PARAM_LOG_PBYTE:
            ret = ret + "PBYTE"
        elif self.log_type == V_PARAM_LOG_PWORD:
            ret = ret + "PWORD"
        elif self.log_type == V_PARAM_LOG_PINT:
            ret = ret + "PINT"
        elif self.log_type == V_PARAM_LOG_ASTR:
            ret = ret + "ASTR"
        elif self.log_type == V_PARAM_LOG_USTR:
            ret = ret + "USTR"
        elif self.log_type == V_PARAM_LOG_PASTR:
            ret = ret + "PASTR"
        elif self.log_type == V_PARAM_LOG_PUSTR:
            ret = ret + "PUSTR"
        elif self.log_type == V_PARAM_LOG_PPASTR:
            ret = ret + "PPASTR"
        elif self.log_type == V_PARAM_LOG_PPUSTR:
            ret = ret + "PPUSTR"
        else:
            assert False
        return ret


class ApiHookBase(object):
    """api 记录断点的基类"""

    def __init__(self, dll_name, api_name, group_name=None, weight=V_WEIGHT_MIDDLE,
                 cstk_filter_depth=1, max_invoke_cnt_runtime=None, handler_check_shall_stop=None,
                 is_fragile=False, is_too_frequent=False):
        """
            @param: dll_name                 : string : api 所属的 DLL 名称
            @param: api_name                 : string : api 名称
            @param: group_name               : string : (optional, dft=None)所属组的名称
            @param: weight                   : int    : (optional, dft=V_WEIGHT_MIDDLE)有多重要. [V_WEIGHT_IGNORE/...]
            @param: cskt_filter_depth        : int    : (optional, dft=1)调用栈过滤的深度. 为1表示不会有上层调用
            @param: max_invoke_cnt_runtime   : int    : (optional, dft=None)运行时命中多少次后不再 Hook 此 api
            @param: handler_check_shall_stop : method : (optional, dft=None)方法, 在记录完参数/执行完自定义函数之后, 检查是否需要暂停调试器
                                             :        : 只在调试器为 GUI 调试器时调用
            @param: is_fragile               : bool   : (optional, dft=False)是否容易导致被调试进程崩溃
            @param: is_too_frequent          : bool   : (optional, dft=False)是否可能会被频繁调用
        """
        self.dll_name = dll_name
        self.api_name = api_name

        if not group_name or len(group_name) == 0:
            self.group_name = "default"
        else:
            self.group_name = group_name

        self.weight = weight

        if cstk_filter_depth:
            self.cstk_filter_depth = cstk_filter_depth
        else:
            self.cstk_filter_depth = 0

        if max_invoke_cnt_runtime:
            self.max_invoke_cnt_runtime = max_invoke_cnt_runtime
        else:
            self.max_invoke_cnt_runtime = 0

        self.handler_check_shall_stop = handler_check_shall_stop
        self.is_fragile = is_fragile
        self.is_too_frequent = is_too_frequent

        self.meta = {}  # 单独针对此 api 的设置

    def get_config(self):
        """获取配置, 用于保存到配置文件"""
        return {"dll_name": self.dll_name,
                "group_name": self.group_name,
                "weight": self.weight,
                "max_invoke_cnt_runtime": self.max_invoke_cnt_runtime,
                "is_fragile": self.is_fragile,
                "is_too_frequent": self.is_too_frequent,
                "meta": self.meta,
                }

    def api_invoke(self, dbg):
        """api命中. 子类实现"""
        pass

    def __str__(self):
        """字符串表示"""
        return "(%d)%s-%s" % (self.cstk_filter_depth, self.dll_name, self.api_name)

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


class ApiHookLogParams(ApiHookBase):
    """命中 api 断点时只记录指定的参数"""

    def __init__(self, dll_name, api_name, group_name=None, weight=V_WEIGHT_MIDDLE,
                 param_log_ctrl_list=None, cstk_filter_depth=1, max_invoke_cnt_runtime=None,
                 handler_check_shall_stop=None, is_fragile=False, is_too_frequent=False):
        """
            @param: param_log_ctrl_list : list or None : (optional, dft=None)ParamLogCtrl 对象列表. 指定如何记录 api 的参数
        """
        ApiHookBase.__init__(self, dll_name, api_name, group_name=group_name, weight=weight,
                             cstk_filter_depth=cstk_filter_depth, max_invoke_cnt_runtime=max_invoke_cnt_runtime,
                             is_fragile=is_fragile, is_too_frequent=is_too_frequent)
        self.param_log_ctrl_list = param_log_ctrl_list

    def api_invoke(self, dbg):
        """api命中, 记录参数"""
        pass

    def __str__(self):
        return "params(%s)" % ApiHookBase.__str__(self)

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


class ApiHookCustom(ApiHookBase):
    """命中 api 断点时执行自定义的回调函数"""

    def __init__(self, dll_name, api_name, handler_api_invoke, group_name=None, weight=V_WEIGHT_MIDDLE,
                 cstk_filter_depth=1, max_invoke_cnt_runtime=None, handler_check_shall_stop=None, is_fragile=False,
                 is_too_frequent=False):
        """
            @param: handler_api_invoke : method : 命中 api 断点时执行的回调函数
                  :                    :        : 返回值: (参数字典, meta, True/False). 参见 api_hook_invoke.callback_api_hook_hit()
        """
        ApiHookBase.__init__(self, dll_name, api_name, group_name=group_name, weight=weight,
                             cstk_filter_depth=cstk_filter_depth, max_invoke_cnt_runtime=max_invoke_cnt_runtime,
                             handler_check_shall_stop=handler_check_shall_stop, is_fragile=is_fragile, is_too_frequent=is_too_frequent)
        self.handler_api_invoke = handler_api_invoke

    def api_invoke(self, dbg):
        """api命中, 调用回调"""
        pass

    def __str__(self):
        return "custom(%s)" % ApiHookBase.__str__(self)

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
