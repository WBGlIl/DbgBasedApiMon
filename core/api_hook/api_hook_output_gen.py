# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals

from api_hook_output_def import *
from util_dbg import *

# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 日志


def _log(msg):
    log(__file__, msg)


def _warn(msg):
    warn(__file__, msg)


def _error(msg):
    error(__file__, msg)


# ---------------------------------------------------------------------------
# 回调

def callback_proc_exit(dbg):
    """进程退出, 把收集内容导出到文件, 或传输给 IDA"""
    print("[api_hook]proc exit")


# ---------------------------------------------------------------------------
# 类 - 函数


def add_api_hit_record(api_name, stacks, param_str=None):
    """
        添加 api 命中记录

        @param: api_name  : string : api name
        @param: stacks    : list   : list of StackFrame() object
        @param: param_str : string : (optional, dft=None)param string
    """
    global v_tmp_api_record_list
    v_tmp_api_record_list.append((api_name, stacks, param_str))


def api_summary_no_stacks__add_record(summary, param_str):
    """
        @param: summary   : obj    : obj of _share_this.ApiHitNoStacks()
        @param: param_str : string : api call param description
    """
    if param_str and param_str not in summary.param_str_list:
        summary.param_str_list.append(param_str)

    summary.call_count = summary.call_count + 1

    return summary

# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
