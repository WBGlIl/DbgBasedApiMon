# -*- coding: utf-8 -*-

"""
1. 只针对 pydbg / TitanEngineDbg / winappdbg
"""

from __future__ import print_function
# # from __future__ import unicode_literals

import os

# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


def filter_api_hook_list(api_hook_list, api_config, api_select_config):
    """过滤 api_hook, 去掉禁用的/不要的之类的"""

    # 去除无效的
    tmp_valid = []
    for api_hook in api_hook_list:
        if len(api_hook.api_name) != 0 and len(api_hook.dll_name) != 0:
            tmp_valid.append(api_hook)

    # 根据配置中的是否启用
    tmp_enabled = []
    for api_hook in tmp_valid:
        if api_config[api_hook.api_name]["is_enabled"]:
            tmp_enabled.append(api_hook)

    # 根据 选择配置 中的 weight/group_name/dll_name/is_fragile/is_too_frequent 等过滤

    # group_name
    tmp_group = []
    if "all" in api_select_config["group_name_list"]:
        tmp_group = tmp_enabled
    else:
        for api_hook in tmp_enabled:
            if api_hook.group_name in api_select_config["group_name_list"]:
                tmp_group.append(api_hook)

    # weight
    tmp_weight = []
    if api_select_config["weight"] == 1:
        tmp_weight = tmp_group
    else:
        for api_hook in tmp_group:
            if api_hook.weight >= api_select_config["weight"]:
                tmp_weight.append(api_hook)

    # dll_name
    tmp_dll_name = []
    if "all" in api_select_config["dll_name_list"]:
        tmp_dll_name = tmp_weight
    else:
        for api_hook in tmp_weight:
            if api_hook.dll_name in api_select_config["dll_name_list"]:
                tmp_dll_name.append(api_hook)

    # is_fragile
    tmp_is_fragile = []
    if api_select_config["is_fragile"]:
        tmp_is_fragile = tmp_dll_name
    else:
        for api_hook in tmp_dll_name:
            if not api_hook.is_fragile:
                tmp_is_fragile.append(api_hook)

    # is_too_frequent
    tmp_is_too_frequent = []
    if api_select_config["is_too_frequent"]:
        tmp_is_too_frequent = tmp_is_fragile
    else:
        for api_hook in tmp_is_fragile:
            if not api_hook.is_too_frequent:
                tmp_is_too_frequent.append(api_hook)

    ret = tmp_is_too_frequent

    return ret

# ---------------------------------------------------------------------------
# main


def main():

    # 导入命令行调试器
    from pydbg._dbg_proxy import Debugger
    # from winappdbg._dbg_proxy import Debugger()
    dbg = Debugger()

    # 设置调试器
    from core import _core
    _core.dbg = dbg

    from core.api_hook import api_hook_loader
    from core.api_hook import api_hook_select_config
    from core.debugee_hook import debugee_hook_loader

    # 加载并导入 api/debugee 配置
    api_config, api_global_config = api_hook_loader.loader_load_api_hook_config()
    api_hook_select_config.load_api_hook_select_config()
    api_select_config = api_hook_select_config.api_hook_select_config

    debugee_config, debugee_global_config = debugee_hook_loader.loader_load_debugee_config()

    # 加载并设置 api_hook 列表和 debugee_hook 列表
    api_hook_list = api_hook_loader.loader_load_api_hook()
    debugee_hook_list = debugee_hook_loader.loader_load_debugee_hook()
    print("api_hook count before filter: %d" % len(api_hook_list))
    api_hook_list_filtered = filter_api_hook_list(api_hook_list, api_config, api_select_config)
    print("api_hook count before after: %d" % len(api_hook_list_filtered))
    dbg.set_hook_list(api_hook_list_filtered, debugee_hook_list)

    # 设置 api_hook/debugee_hook 命中的回调
    from core.api_hook import api_hook_invoke
    from core.debugee_hook import debugee_hook_invoke
    dbg.set_hook_hit_callback(api_hook_invoke.callback_api_hook_hit, debugee_hook_invoke.callback_debugee_hook_hit)

    # 设置进程结束的回调
    from core.api_hook import api_hook_output_gen
    from core.debugee_hook import debugee_hook_output_gen
    dbg.set_proc_exit_callback(api_hook_output_gen.callback_proc_exit, debugee_hook_output_gen.callback_proc_exit)

    from pydbg._dbg_config import dbg_config
    dbg_config["when_install_api_hook"] = "proc_create"

    # 设置调试的对象
    # debugee_name = r"1111.exe"
    # debugee_name = r"C:\Windows\notepad.exe"
    # debugee_cmdline = ""
    debugee_name = dbg_config["debugee_path"]
    debugee_cmdline = dbg_config["debugee_cmdline"]

    # 设置感兴趣的模块为被调试模块. 可以自己添加其他的模块
    # TODO: 不应该这里调用
    from core.api_hook import api_hook_config
    api_hook_config.api_global_config_runtime["interested_module_names"].append(os.path.split(debugee_name)[1])

    # 启动调试
    dbg.xuck_it(os.path.abspath(debugee_name), debugee_cmdline)

    # !+ 别在 Win10 系统调试


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
