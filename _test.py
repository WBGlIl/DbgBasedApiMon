# -*- coding: utf-8 -*-

"""
1. 随便测点儿什么
"""

from __future__ import print_function
# # from __future__ import unicode_literals


# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


# ---------------------------------------------------------------------------
# main


class A:

    def __init__(self):
        self.handler = None

    def set_handler(self, handler):
        self.handler = handler

    def invoke_handler(self):
        self.handler(self, "param 1", "param 2")

    def a_do(self):
        print("a doing")


class B:

    def __init__(self):
        self.a = A()
        self.a.set_handler(self.real_handler)

    def real_handler(self, *x, **xx):
        """A 在调用此回调时传递了的所有参数, 都在 self 后面"""
        print("hello")

        # 从对象 A 开始的所有参数, 都在 x(tuple) 里面
        print(x)
        print(xx)

        # 从 x 获取第1个参数, 也就是 A 传递的第1个参数, 也就是 A 对象本身
        x[0].a_do()


if __name__ == "__main__":
    b = B()
    b.a.invoke_handler()


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
