# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals

import pprint

from core_def import *
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
# 类 - 函数


class CallStack(object):
    """调用堆栈"""
    def __init__(self, stacks=[]):
        """
            @param: stacks : list : StackFrame() 对象的列表
        """
        self.frames = frames

    def __equals__(self, other):
        """判断2个调用栈是否相同"""
        if len(self.frames) != len(other.frames):
            return False

        for frame_1, frame_2 in zip(self.frames, other.frames):
            # 通过每帧的返回地址判断
            if frame_1.to_addr != frame_2.to_addr:
                return False
        return True


class ApiHitRaw(object):
    """
        api 命中的原始数据.
        每次 api 命中都添加1项, 但不解析.
        只在需要时解析为 ApiHitWithStacks/ApiHitNoStacks 对象
    """
    def __init__(self, index, api_name, call_stack_raw):
        """
            @param: index          : int    : 总共第几次 api 命中
            @param: api_name       : string : 命中的 api 名称
            @param: call_stack_raw : list   : CallStackRaw() 对象
        """
        self.index = index
        self.api_name = api_name
        self.call_stack_raw = call_stack_raw

        self.params = None                 # 调用参数 - 参数名:参数值 的字典
        self.meta_list = None              # 附加信息 - 字符串列表
        self.is_pass = False               #

        self.post_params = None            #
        self.post_meta_list = None         #

    def set_is_pass(self, is_pass):
        """设置是否通过了层层过滤到达获取参数/执行回调"""
        self.is_pass = is_pass

    def set_params(self, params):
        """设置调用的参数"""
        self.params = params

    def add_meta(self, meta):
        """设置一些数据"""
        if self.meta_list:
            self.meta_list.append(meta)
        else:
            self.meta_list = [meta]

    def set_post_params(self, post_params):
        """在 api 返回处安装 hook 命中后收集的参数信息"""
        self.post_params = post_params

    def add_post_meta(self, post_meta):
        """在 api 返回处安装 hook 命中后收集的其他信息"""
        self.post_meta_list.append(post_meta)

    def __str__(self):
        """字符串表示 - 用于打印"""
        lines = ["%d - %s" % (self.index, self.api_name)]
        lines.append(str(self.call_stack_raw))
        if self.params and len(self.params) != 0:
            lines.append(pprint.pformat(self.params))
        if self.meta_list and len(self.meta_list) != 0:
            lines.append(pprint.pformat(self.meta_list))
        return pprint.pformat(lines)

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


class ApiHitWithStacks(object):
    """解析后的 api 命中. 调试器识别出了堆栈. 解析堆栈中的某些内容"""
    def __init__(self, to_addr, api_name, from_func_name):
        """
            @param: to_addr        : int    : 此次命中 api 的顶层 api 的返回地址
                  :                :        : 是设置的感兴趣模块的地址
            @param: api_name       : string : 实际命中的 api 名称
                  :                :        : 不是顶层的 api
            @param: from_func_name : string : 调用顶层 api 的函数名称
                  :                :        : 不一定是实际命中的 api
                  :                :        : (不一定有??)
        """
        assert to_addr != 0

        self.to_addr = to_addr
        self.api_name = api_name
        self.from_func_name = from_func_name

        self.stacks_list = []
        self.param_str_list = []

        self.call_count = 0

    def add_record(summary, api_name, from_func_name, stacks, param_str=None):
        """
            @param: summary        : obj    : obj of _share_this.ApiHitWithStacks()
            @param: api_name       : string : api name that truely hit breakpoint
            @param: from_func_name : string :
            @param: stacks         : list   : list of StackFrame() object
            @param: param_str      : string : (optional, dft=None)param string
        """
        # todo: special samples, different api may return to same to_addr, because sample invoke api in this way: call eax...
        if summary.api_name != api_name:

            global v_tmp_is_pt_parse_api_summary_collision
            if v_tmp_is_pt_parse_api_summary_collision:
                _log("-" * 100)
                _log("existing summary details: ")
                for line in summary.lines():
                    _log("    %s" % line)
                _log("")
                _log("record to add details:")
                _log("    api_name: %s" % api_name)
                _log("    from_func_name: %s" % from_func_name)
                _log("    stacks details(depth: %d): " % len(stacks))
                for stack in stacks:
                    _log("        %s" % stack)
                _log("-" * 100)
            # assert False
            return summary

        assert summary.api_name == api_name
        if summary.from_func_name != from_func_name:
            _log("-" * 100)
            _log(">>> not equal from_func_name: %s vs %s" % (summary.from_func_name, from_func_name))
            _log("-" * 100)
            # assert False
            return summary
        assert len(stacks) != 0

        if not _share_this.has_stacks(summary.stacks_list, stacks):
            summary.stacks_list.append(stacks)

        if param_str and param_str not in summary.param_str_list:
            summary.param_str_list.append(param_str)

        summary.call_count = summary.call_count + 1

        return summary

    def __str__(self):
        """"""
        return "to_addr: %.8X, api: %s, from_name: %s, call_count: %d, stacks_cnt: %d param_count: %d" % (self.to_addr, self.api_name, self.from_func_name, self.call_count, len(self.stacks_list), len(self.param_str_list))

    def __repr__(self):
        """表示: 字符串列表"""
        lines = [str(self)]
        lines.append("    stacks:")
        for stacks in self.stacks_list:
            lines.append("    stack:")
            for stack in stacks:
                lines.append("        %s" % str(stack))
        lines.append("    params:")
        for param_str in self.param_str_list:
            lines.append("        %s" % param_str)
        return lines


class ApiHitNoStacks(object):
    """解析后的 api 命中. 调试器未能识别出堆栈"""
    def __init__(self, api_name):
        """
        """
        self.api_name = api_name
        self.param_str_list = []

        self.call_count = 0

    def __str__(self):
        """"""
        return "api: %s, call_count: %d, param_count: %d" % (self.api_name, self.call_count, len(self.param_str_list))

    def __repr__(self):
        """
            @return: list : a list of strings
        """
        lines = [str(self)]
        for param_str in self.param_str_list:
            lines.append("    %s" % param_str)
        return lines


def has_stacks(stacks_list, frames):
    """
        @param: stacks_list : list : CallStack() 对象列表
        @param: frames      : list : a list of StackFrame() objects
    """
    if len(stacks_list) == 0:
        return False

    for stacks in stacks_list:
        if stacks.is_same_stacks(frames):
            return True

    return False


def is_stacks_has_None_md(stacks):
    """
        check if from_md_name or to_md_name of any stack in stacks is "None", meaning these stacsk went through "heap" or "stack"

        @param: stacks : list : a list of StackFrame() object

        @return: bool :
               : None :

        !+ do not check to_md_name of last stack, which shall always be ""
        !+ it's "pickle loader"'s responsibility to check if stacks has None md.
    """
    for i in range(len(stacks) - 1):

        stack = stacks[i]
        if stack.to_md_name is None or stack.to_md_name == "":
            return True
        if stack.from_md_name is None or stack.from_md_name == "":
            return True

    return stacks[-1].from_md_name is None or stacks[-1].from_md_name == ""


class DebugeeInfo(object):
    def __init__(self):
        pass


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
