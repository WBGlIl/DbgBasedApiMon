# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals

import pprint

from _util.util import *


# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


class StackFrameSideBase(object):
    """栈帧的1边. From 或者 To"""
    def __init__(self, addr, hex_context):
        self.addr = addr
        self.hex_context = hex_context

    def __str__(self):
        raise Exception("")

    def __repr__(self):
        return self.__str__()


class StackFrameSideMd(StackFrameSideBase):
    """栈帧的1边, From 或者 To. 属于进程加载的模块"""
    def __init__(self, addr, hex_context, md_name, md_base):
        StackFrameSideBase.__init__(self, addr, hex_context)
        self.md_name = md_name
        self.md_base = md_base

    def __str__(self):
        raise Exception("")

    def __repr__(self):
        return self.__str__()


class StackFrameSideMdWithSym(StackFrameSideMd):
    """栈帧的1边, From 或者 To. 属于进程加载的模块, 而且调试器识别出了符号"""
    def __init__(self, addr, hex_context, md_name, md_base, func_name, func_offset):
        StackFrameSideMd.__init__(self, addr, hex_context, md_name, md_base)
        self.func_name = func_name
        self.func_offset = func_offset

    def __str__(self):
        """字符串表示 - 1行"""
        return "[%s %s.%s.0x%.8X]" % (to_hex(self.hex_context[:4]), self.md_name, self.func_name, self.func_offset)

    def __repr__(self):
        return self.__str__()


class StackFrameSideMdNoSym(StackFrameSideMd):
    """栈帧的1边, From 或者 To. 属于进程加载的模块, 但是调试器未识别符号"""
    def __init__(self, addr, hex_context, md_name, md_base):
        StackFrameSideMd.__init__(self, addr, hex_context, md_name, md_base)

    def __str__(self):
        """字符串表示 - 1行"""
        return "[%s %s.0x%.8X]" % (to_hex(self.hex_context[:4]), self.md_name, self.addr - self.md_base)

    def __repr__(self):
        return self.__str__()


class StackFrameSideHeap(StackFrameSideBase):
    """栈帧的1边, From 或者 To. 属于堆上分配的1块内存"""
    def __init__(self, addr, hex_context, heap_base):
        StackFrameSideBase.__init__(self, addr, hex_context)
        self.heap_base = heap_base

    def __str__(self):
        """字符串表示 - 1行"""
        return "[%s %s.0x%.8X]" % (to_hex(self.hex_context[:4]), self.heap_base, self.addr - self.heap_base)

    def __repr__(self):
        return self.__str__()


class StackFrameSideInvalid(StackFrameSideBase):
    """栈帧的1边, From 或者 To. 但是地址无效"""
    def __init__(self, addr, hex_context=None):
        StackFrameSideBase.__init__(self, addr, hex_context)

    def __str__(self):
        """字符串表示 - 1行"""
        return "[0x%.8X(Invalid)]" % (self.addr)
    __repr__ = __str__


class StackFrameRaw(object):
    """完整栈帧. 包括 From To 两端"""
    def __init__(self, frame_from, frame_to):
        self.frame_from = frame_from
        self.frame_to = frame_to

    def __str__(self):
        """字符串表示 - 1行"""
        return "%s <- %s" % (self.frame_to, self.frame_from)

    def __repr__(self):
        return self.__str__()


class CallStackRaw(object):
    """完整调用栈, 原始版, 调试器发送过来的. 与之相对的是 api_hook/debugee_hook 保存的堆栈, 是解析过的"""
    def __init__(self):
        self.stack_frame_raw_list = []
        self.meta_list = []

    def append_frame(self, stack_frame_raw):
        """添加栈帧"""
        self.stack_frame_raw_list.append(stack_frame_raw)

    def add_meta(self, meta):
        """添加 meta 信息"""
        self.meta_list.append(meta)

    def __len__(self):
        """当前长度"""
        return len(self.stack_frame_raw_list)

    def __iter__(self):
        """遍历时, 遍历每个 frame"""
        return iter(self.stack_frame_raw_list)

    def __str__(self):
        """字符串表示"""
        lines = []
        for frame_raw in self.stack_frame_raw_list:
            lines.append(str(frame_raw))
        lines.append(pprint.pformat(self.meta_list))
        return pprint.pformat(lines)

    def __repr__(self):
        return self.__str__()


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    x = StackFrameSideBase(123, "")


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
