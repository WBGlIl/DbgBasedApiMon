# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals

import six
import inspect


# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


def loader_load_debugee_config():
    """
        加载 debugee 配置

        @return: tuple : (debugee_config, debugee_global_config)
    """
    return (None, None)


def loader_load_debugee_hook():
    """加载文件中定义的 debugee_hook 列表"""
    # 解析 debugee_hook_list 中的 object
    import debugee_hook_list
    for obj in six.itervalues(vars(debugee_hook_list)):
        if inspect.isclass(obj):
            print(obj)


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
