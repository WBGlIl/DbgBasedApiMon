# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# # from __future__ import unicode_literals

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))                          # core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))         # repo-pydbg

import json

from _util.base import *

# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


# ---------------------------------------------------------------------------
# 日志


def _log(msg):
    print(msg)


def _warn(msg):
    print(msg)


def _error(msg):
    print(msg)


__api_hook_select_config_default = ConfigItemContainer([
    ("group_name_list", ["all"], """
安装 api_hook 的组的名称列表.
有 "all" 表示会安装所有组, 其他的组名会忽略.
组之间用 ";" 分隔"""),

    ("weight", 5, """
安装 api_hook 的组的重要程度.
可选值为: 1 3 5 7 9."""),

    ("dll_name_list", ["all"], """
安装 api_hook 的模块的名称列表.
有 "all" 表示会安装所有模块, 其他的模块名会忽略.
模块名之间用 ";" 分隔
"""),

    ("is_fragile", False, """
是否安装较大可能导致被调试进程崩溃的 api_hook"""),

    ("is_too_frequent", False, """
是否安装调用特别频繁的 api_hook"""),

])


api_hook_select_config = ConfigItemContainer()


# ---------------------------------------------------------------------------


def __api_hook_select_config_file_name():
    """配置文件的绝对路径 - 当前 .py 目录下"""
    return os.path.join(os.path.dirname(__file__), "api_hook_select_config.json")


def load_api_hook_select_config():
    """从磁盘文件中加载 api_hook选择 所有配置"""

    # 直接作用于全局变量, 执行完之后全局变量就是 代码配置+文件配置 的混合版
    global api_hook_select_config
    global __api_hook_select_config_default

    file = os.path.abspath(__api_hook_select_config_file_name())
    if not os.path.exists(file) or os.path.getsize(file) == 0:

        # 配置文件不存在, 认为首次运行或者配置文件被删除
        # 从代码中获取默认配置, 并将配置写入文件

        api_hook_select_config.replace_by(__api_hook_select_config_default)

        # 保存到磁盘
        save_api_hook_select_config(api_hook_select_config.purify())

    else:
        # 配置文件存在, 读取配置文件, 与代码中的进行对比, 判断代码是否进行了更新
        with open(file) as f:
            api_hook_select_config_file = json.load(f)

            # 用文件配置覆盖代码配置
            api_hook_select_config.replace_by(__api_hook_select_config_default)
            api_hook_select_config.update_by_purified_dict(api_hook_select_config_file)

            # 根据配置个数判断代码是否更新
            if len(api_hook_select_config_file) != len(__api_hook_select_config_default):

                # 保存新的到磁盘
                save_api_hook_select_config(api_hook_select_config.purify())


def save_api_hook_select_config(api_hook_select_config_new):
    """将调试器配置保存到磁盘"""

    file = os.path.abspath(__api_hook_select_config_file_name())
    if os.path.exists(file):
        try:
            os.remove(file)
        except Exception, e:
            _log("del old api hook select config file failed. exp: %s" % e)
    with open(file, "w") as f:
        f.write(json.dumps(api_hook_select_config_new, ensure_ascii=False, indent=4))

    _log("api hook select config saved!")


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    load_api_hook_select_config()


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
