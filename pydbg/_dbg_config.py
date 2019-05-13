# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals


import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))  # repo-pydbg

import json

from _util.base import ConfigItemContainer


# ---------------------------------------------------------------------------
# 日志


def _log(msg):
    print(msg)


def _warn(msg):
    print(msg)


def _error(msg):
    print(msg)


# ---------------------------------------------------------------------------
# 变量


__dbg_config_default = ConfigItemContainer([
    ("debugee_path", "C:\\1111.exe", """
调试文件路径"""),

    ("debugee_cmdline", "", """
调试命令行"""),

    ("log_level", "info", """
日志级别 - ["info", "warn", "error"]"""),

    ("is_hide_debugger", False, """
是否隐藏调试器"""),

    ("when_install_api_hook", "proc_create", """
安装 api_hook 的时机
["proc_create", "exe_load/exe_ep", "dll_load/dll_ep", "addr_hit", "dynamic"]"""),

    ("install_api_hook_opp_dll_name", "", """
如果安装 api_hook 的时机是 "dll_load/dll_ep", 这个指定 dll 名称"""),

    ("install_api_hook_opp_hit_addr", 0, """
如果安装 api_hook 的时机是 "addr_hit", 这个指定命中地址"""),

])


# 全局配置. 这些由其他模块引用的全局变量, 只能在这里 "=" 1次.
# 不然人家在 .py 头部 import, 你在这个文件的其他地方又 "=" 了, 人家就用不了了
dbg_config = ConfigItemContainer()


# ---------------------------------------------------------------------------
# 类 - 函数


def __dbg_config_file_name():
    """配置文件的绝对路径 - 当前 .py 目录下"""
    return os.path.join(os.path.dirname(__file__), "dbg_config.json")


def load_dbg_config():
    """从磁盘文件中加载 调试器 所有配置"""

    # 直接作用于全局变量, 执行完之后全局变量就是 代码配置+文件配置 的混合版
    global dbg_config
    global __dbg_config_default

    file = os.path.abspath(__dbg_config_file_name())
    if not os.path.exists(file) or os.path.getsize(file) == 0:

        # 配置文件不存在, 认为首次运行或者配置文件被删除
        # 从代码中获取默认配置, 并将配置写入文件

        dbg_config.replace_by(__dbg_config_default)

        # 保存到磁盘
        save_dbg_config(dbg_config.purify())

    else:
        # 配置文件存在, 读取配置文件, 与代码中的进行对比, 判断代码是否进行了更新
        with open(file) as f:
            dbg_config_file = json.load(f)

            # 用文件配置覆盖代码配置
            dbg_config.replace_by(__dbg_config_default)
            dbg_config.update_by_purified_dict(dbg_config_file)

            # 根据配置个数判断代码是否更新
            if len(dbg_config_file) != len(__dbg_config_default):

                # 保存新的到磁盘
                save_dbg_config(dbg_config.purify())


def save_dbg_config(dbg_config_new):
    """将调试器配置保存到磁盘"""

    file = os.path.abspath(__dbg_config_file_name())
    if os.path.exists(file):
        try:
            os.remove(file)
        except Exception, e:
            _log("del old dbg config file failed. exp: %s" % e)
    with open(file, "w") as f:
        f.write(json.dumps(dbg_config_new, ensure_ascii=False, indent=4))

    _log("dbg config saved!")


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    load_dbg_config()
    import pprint
    pprint.pprint(dbg_config)

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
