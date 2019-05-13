# -*- coding: utf-8 -*-

"""
跟 api_hook 有关的配置

1. api_hook_list.py 中的代码尽量少改动. 如果需要改动, 尽量改配置文件中的
    - 代码有更新时, 之前[配置]的 api 不至于废掉
    -

"""

from __future__ import print_function
# # from __future__ import unicode_literals

import six
import json
# import inspect

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))                          # core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))         # repo-pydbg

from api_hook_def import *
from util_dbg import *
from _util.base import *


# ---------------------------------------------------------------------------
# 日志


def _log(msg):
    log(__file__, msg)


def _warn(msg):
    warn(__file__, msg)


def _error(msg):
    error(__file__, msg)


# ---------------------------------------------------------------------------
# 针对每个 api 的配置:


"""
属于 ApiHookBase 类的:
    - dll_name/group_name/weight/max_invoke_cnt_runtime
    - api_hook_list.py 中创建变量的值是默认值, 用于生成默认的 api_hook_config.json
不属于的:
    - is_enabled

"""


def get_api_config_default():
    """
    获取所有 api 的默认配置

    @return: dict : 以 api_name 为 key 的字典
    """
    api_config_default = {}

    import api_hook_list
    for obj in six.itervalues(vars(api_hook_list)):
        if isinstance(obj, ApiHookBase):
            # print(type(obj), obj)
            api_config_default[obj.api_name] = obj.get_config()
            api_config_default[obj.api_name]["is_enabled"] = True

    return api_config_default


def override_api_config(api_config, api_config_other):
    """
    重新设置 api_config 的内容. 只是为了避免对 api_config 的多次 "="

    @param: api_config       : obj : ConfigItemContainer()对象
    @param: api_config_other : obj : ConfigItemContainer()对象
    """
    api_config.clear()
    for k, v in api_config_other.items():
        api_config[k] = v


# 每个 api_hook 的通用配置
# 在 load_api_hook_config() 设置具体内容
api_config = {}


# ---------------------------------------------------------------------------
# api_hook 的全局配置


# 不需要保存到配置文件
api_global_config_runtime = ConfigItemContainer([
    ("interested_module_names", [], """
在过滤调用栈时, 如果在指定的层数之内出现这些模块, 则表示是我们感兴趣的, 需要记录.
默认为 [], 在调试器启动时会自动添加调试的模块""")

])


# 需要保存到配置文件
__api_global_config_default = ConfigItemContainer([
    ("is_disable_all", False, """
是否禁用所有 api 监控.
如果禁用, 将不安装任何 api_hook"""),

    ("is_calc_api_invoke_time", False, """
是否统计 api 命中处理所花的时间.
用于测试性能."""),

    ("export_dir", "__files", """
保存中间文件的目录.
例如: 删除的文件/目录、发送/接收网络数据的 pcap 文件等"""),

    ("is_backup_remove_stuff", False, """
是否备份删除的文件/目录等内容.
默认为 False, 表示不备份"""),

    ("is_filter_call_stack", True, """
api 命中时是否过滤调用栈.
因为只对"底层" api 下断, 所以需要通过过滤检查 api 的实际发起者是不是我们感兴趣的模块.
如果选择否, 则每次 api 命中时都会记录函数参数/调用自定义回调等(命中次数达到上限还是会移除的)"""),

    ("is_intrude_debugee", True, """
是否对被调试进程执行写入等操作.
某些样本调试时写入进程内存可能导致进程崩溃, 则禁用此选项.
当前, 禁用此选项会导致某些功能失效, 例如: 确保所有socket操作成功、伪装文件路径等"""),

    ("fake_module_file_name", "", """
伪装为新的文件路径"""),

    ("fake_tick_start", 0, """
第1次调用 GetTickCount() 的返回值.
可用于绕过某些只在系统启动一段时间内执行的行为.
为 0 表示不修改."""),

    ("fake_systime_start", 0, """
伪造的首次调用 GetSystemTime() 返回的时间.
之后每次调用 GetSystemTime() 都会根据此时间进行修改, 同时会考虑到 SleepEx() 函数等
为 0 表示不修改"""),

    ("is_shorten_sleep", True, """
是否修改 SleepEx() 的参数为1.
可用于绕过某些使用 SleepEx() 反调试或者延迟代码执行的行为.
如果设置了 fake_tick_start/fake_systime_start, 在修改后也会对这两个配置对应的值进行修改"""),

    ("is_ignore_all_wait_obj", False, """
是否忽略所有 等待对象 的等待过程.
默认为 False.
为 True 可能导致进程崩溃"""),

    ("is_record_alloc_retn", True, """
是否记录 "分配内存" 时实际分配的内存地址"""),

    ("is_bpmmwrite_alloc_retn", False, """
是否为新分配的内存下写入断点"""),

    ("is_all_socket_success", True, """
是否强制所有 socket api 返回成功"""),

    ("connect_redirect_ip", "", """
有网络连接行为时修改连接的 ip 地址.
例如(192.168.0.107)"""),

    ("connect_redirect_port", 0, """
有网络连接行为时修改连接的端口.
默认为 None, 表示不修改"""),

    ("is_save_send_data_to_file", False, """
是否将发送的数据包保存到 pcap 文件"""),

    ("is_save_recv_data_to_file", False, """
是否将接收的数据包保存到 pcap 文件"""),

    ("is_all_mutex_check_success", False, """
是否将所有的 mutex 检查都通过"""),

    ("success_mutex_name_list", [], """
检查哪些互斥体时保证成功"""),

    ("new_http_connect_url", "", """
发生 HTTP 连接时更改为此 url. api为: InternetConnectA()"""),

    ("is_all_access_success", False, """
时所有 access 返回成功"""),

])


# 全局配置. 这些由其他模块引用的全局变量, 只能在这里 "=" 1次.
# 不然人家在 .py 头部 import, 你在这个文件的其他地方又 "=" 了, 人家就用不了了
api_global_config = ConfigItemContainer()


# ---------------------------------------------------------------------------
# api_hook 的所有配置


def __api_hook_config_file_name():
    """配置文件的绝对路径 - 当前 .py 目录下"""
    return os.path.join(os.path.dirname(__file__), "api_hook_config.json")


def load_api_hook_config():
    """从磁盘文件中加载 api_hook 所有配置"""

    # 直接作用于全局变量, 执行完之后全局变量就是 代码配置+文件配置 的混合版
    global api_config
    global api_global_config
    global __api_global_config_default
    __api_config_default = get_api_config_default()

    file = os.path.abspath(__api_hook_config_file_name())
    if not os.path.exists(file) or os.path.getsize(file) == 0:

        # 配置文件不存在, 认为首次运行或者配置文件被删除
        # 从代码中获取默认配置, 并将配置写入文件

        override_api_config(api_config, __api_config_default)
        api_global_config.replace_by(__api_global_config_default)

        # 保存到磁盘
        save_api_hook_config(api_config_new=api_config, api_global_config_new=api_global_config.purify())

    else:
        # 配置文件存在, 读取配置文件, 与代码中的进行对比, 判断代码是否进行了更新
        with open(file) as f:
            api_hook_config = json.load(f)
            api_config_file = api_hook_config["api_config"]
            api_global_config_file = api_hook_config["api_global_config"]

            is_save_new = False

            # api 配置

            # 用文件配置覆盖代码配置
            override_api_config(api_config, __api_config_default)
            for k, v in api_config.items():
                if k in api_config_file:
                    api_config[k] = api_config_file[k]

            # 根据 api 的个数判断代码是否更新
            # 如果更新的是 api 配置里面的具体内容, 呵呵, 请重新配置一遍吧
            if len(api_config_file) == len(__api_config_default):

                # 还是这么些 API
                pass
            else:
                # api 个数发生变化, 新的 api 配置保存至文件
                is_save_new = True

            # 根据全局配置的个数判断代码是否更新
            if len(api_global_config_file) == len(__api_global_config_default):
                pass

            # 全局配置

            # 用文件配置覆盖代码配置
            api_global_config.replace_by(__api_global_config_default)
            api_global_config.update_by_purified_dict(api_global_config_file)

            # 根据配置个数判断代码是否更新
            # 如果更新的是每项配置的具体内容, 呵呵, 自己改配置文件吧
            if len(api_global_config_file) == len(__api_global_config_default):

                # 还是那么些全局配置
                pass
            else:
                # 全局配置个数发生变化, 需要保存新的配置文件
                is_save_new = True

            # 保存新配置到磁盘

            if is_save_new:
                save_api_hook_config(api_config_new=api_config, api_global_config_new=api_global_config.purify())


def save_api_hook_config(api_config_new=None, api_global_config_new=None):
    """
    将 api_hook 所有配置保存到磁盘

    @param: api_config_new        : dict :
    @param: api_global_config_new : dict :

    全局变量 api_config / api_global_config 可能已经设置完毕, 这里别改这些. 毕竟只负责保存...
    """

    # api 配置

    _log("collect new api config...")
    if api_config_new is None:

        # 代码未更新, 但在界面修改了配置. 加载到 x64dbg/OD 等的插件中, 运行时保存

        # 获取所有 api 的默认配置, 并用当前使用的配置进行覆盖
        # 以代码中获取的默认配置为基础, 不会产生冗余配置

        global api_config
        api_config_new = get_api_config_default()
        for k, v in api_config_new.items():
            if k in api_config:
                api_config_new[k] = api_config[k]
    else:
        # 代码进行了更新, 但配置文件未更新. 将新增加的 api 的默认配置写入文件
        # !+ 对于代码中去掉的 api, 这里是已经去除的, 所以无需担心
        pass

    # 全局配置

    _log("collect new api global config...")
    if api_global_config_new is None:

        # 代码未更新, 但在界面修改了配置. 加载到 x64dbg/OD 等的插件中, 运行时保存

        # 获取默认的全局配置, 并用当前使用的配置进行覆盖
        # 以代码中写死的默认配置为基础, 不会产生冗余配置

        global api_global_config
        global __api_global_config_default
        api_global_config_new = __api_global_config_default.purify()
        for k, v in api_global_config_new.items():
            if k in api_global_config:
                api_global_config_new[k] = api_global_config[k]
    else:
        # 代码进行了更新, 但配置文件未更新. 将新增加的默认全局配置写入文件
        # !+ 对于代码中去掉的全局配置, 这里是已经去除的, 所以无需担心
        pass

    # 保存到磁盘

    _log("saving all api_hook config to disk...")
    api_hook_config_new = {
        "api_config": api_config_new,
        "api_global_config": api_global_config_new
    }
    file = os.path.abspath(__api_hook_config_file_name())
    if os.path.exists(file):
        try:
            os.remove(file)
        except Exception, e:
            _log("del old api_hook config file failed. exp: %s" % e)
    with open(file, "w") as f:
        f.write(json.dumps(api_hook_config_new, ensure_ascii=False, indent=4))

    _log("api_hook config saved!")


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    """测试"""
    import pprint

    def _pt_api_config():
        global api_config
        pprint.pprint(api_config)

    def _pt_api_global_config():
        global api_global_config
        pprint.pprint(api_global_config)

    # 测试
    load_api_hook_config()

    _pt_api_config()
    _pt_api_global_config()


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
