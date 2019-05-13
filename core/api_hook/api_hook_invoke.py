# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals

import datetime

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from api_hook_config import api_global_config, api_global_config_runtime, api_config
from api_hook_output_def import *
from api_hook_def import *


# ---------------------------------------------------------------------------
# 日志


def _log(msg):
    log(__file__, msg)


def _warn(msg):
    warn(__file__, msg)


def _error(msg):
    error(__file__, msg)


# ---------------------------------------------------------------------------
# 变量


runtime_data = {
    "api_hit_count": 0,                      # api_hook 总体命中次数
    "api_hit_history": [],                   # api_hook 全部命中历史. ApiHitRaw() 对象的列表
    "api_hit_count_dict": {},                # api_hook 命中次数字典. api_name 为 key, 此 api 命中次数为 value
    "last_api_name_dict": {},                # 最后命中的 api_name 字典. key 为 tid

}

# ---------------------------------------------------------------------------
# 类 - 函数


def callback_api_hook_hit(dbg, api_hook):
    """
        api_hook 命中的回调

        @return: bool : True 表示继续调试; False 表示调试暂停
                      : 命令行调试器需要忽略返回值
    """
    ret = True

    global runtime_data

    # 统计时间 - 开始时间
    if api_global_config["is_calc_api_invoke_time"]:
        start = datetime.datetime.now()

    # 统计 - 总命中次数
    runtime_data["api_hit_count"] = runtime_data["api_hit_count"] + 1

    # 记录 - 当前线程最后命中的api
    runtime_data["last_api_name_dict"][dbg.cur_tid()] = api_hook.api_name

    # 统计 - 每个 api 命中次数. 如果命中次数到达上限, 需要卸载 api_hook
    if api_hook.api_name not in runtime_data["api_hit_count_dict"]:
        runtime_data["api_hit_count_dict"][api_hook.api_name] = 1
    else:
        runtime_data["api_hit_count_dict"][api_hook.api_name] = runtime_data["api_hit_count_dict"][api_hook.api_name] + 1
    if api_config[api_hook.api_name]["max_invoke_cnt_runtime"] and \
            runtime_data["api_hit_count_dict"][api_hook.api_name] > api_config[api_hook.api_name]["max_invoke_cnt_runtime"]:
        _warn("api hit reach limit. removing api hook: %s" % api_hook)
        dbg.uninstall_api_hook(api_hook.api_name)

    # 创建 ApiHitRaw() 对象并添加至历史纪录
    # 这里有个问题: 需要确保每个调试器给出来的 call_stack_raw 都是相同, 而且最好是现成能用的
    call_stack_raw = dbg.get_call_stack_raw(max_depth=api_global_config["call_stack_depth"], is_fix_api_start=True)
    api_hit_raw = ApiHitRaw(runtime_data["api_hit_count"], api_hook.api_name, call_stack_raw)
    runtime_data["api_hit_history"].append(api_hit_raw)

    # ---------------------------------------------------------------------------
    # 根据调用栈进行过滤

    if not api_global_config["is_filter_call_stack"] or len(call_stack_raw) == 0:
        # 不需要过滤
        is_pass = True

    else:
        # 需要过滤

        is_pass = False

        #
        # 对于 pydbg, 前面获取的调用栈可能是错的. 老实说, pydbg 该自己去改进, 而不是在这里处理
        #

        if len(call_stack_raw) != 0:

            itd_module_names = api_global_config_runtime["interested_module_names"]

            for index, frame_raw in enumerate(call_stack_raw):

                if index < api_hook.cstk_filter_depth:

                    frame_from = frame_raw.frame_from
                    frame_to = frame_raw.frame_to

                    if isinstance(frame_from, StackFrameSideInvalid) or isinstance(frame_to, StackFrameSideInvalid) or \
                            isinstance(frame_from, StackFrameSideHeap) or isinstance(frame_to, StackFrameSideHeap):

                        # From 或者 To 最少有1个无效或者在堆上
                        is_pass = True
                        break

                    if frame_from.md_name in itd_module_names or frame_to.md_name in itd_module_names:

                        # From 或者 To 最少有1个是我们感兴趣的模块
                        is_pass = True
                        break
                else:
                    # 深度过大, 再比较就没有意义了
                    break
        else:
            # 没有调用栈, [可能]不正常, 得记录
            is_pass = True

    # 设置属性
    api_hit_raw.set_is_pass(is_pass)

    # ---------------------------------------------------------------------------

    if is_pass:

        # ---------------------------------------------------------------------------
        # 获取并记录 api 调用参数

        param_dict = {}
        if isinstance(api_hook, ApiHookLogParams):

            # 记录函数参数
            if api_hook.param_log_ctrl_list is None or len(api_hook.param_log_ctrl_list) == 0:

                # 无需记录参数, 只是记录调用
                pass

            else:
                # 获取参数
                for param_log_ctrl in api_hook.param_log_ctrl_list:
                    param_dict[param_log_ctrl.log_name] = param_log_ctrl.get_log(dbg)
        else:
            # 调用自定义处理函数, 返回: (参数字典, meta, True/False)
            # [0] - 参数字典
            # [1] - 额外数据
            # [2] - True/False - 是否暂停调试器
            param_dict, meta_list, ret = api_hook.handler_api_invoke(dbg)
            if meta_list:
                for meta in meta_list:
                    api_hit_raw.add_meta(meta)

        # 设置
        if param_dict:
            api_hit_raw.set_params(param_dict)

        # ---------------------------------------------------------------------------

        # 如果此 api 命中次数达到设置的上限, 则移除此 api_hook
        if api_hook.max_invoke_cnt_runtime and api_hook.max_invoke_cnt_runtime < runtime_data["api_hit_count_dict"][api_hook.api_name]:
            api_hit_raw.add_meta("max api invoke hit(%d). removing api hook" % (api_hook.max_invoke_cnt_runtime))
            dbg.uninstall_api_hook(api_hook.api_name)

    else:
        # 没通过, 就不用做什么了
        pass

    # ---------------------------------------------------------------------------
    # 把解析后的 api_hit_raw 传递给 IDA 和调试器

    # 用 zmq.pub 传递给 IDA
    # TODO

    # 通知调试器
    dbg.notify_api_hit_raw(api_hit_raw)

    # ---------------------------------------------------------------------------

    # 开始时间 - 结束时间
    if api_global_config["is_calc_api_invoke_time"]:
        end = datetime.datetime.now()
        elapse = end - start
        dbg.log("api elasped: %d" % elapse)

    # ---------------------------------------------------------------------------

    # 返回
    return ret


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
