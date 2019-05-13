# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals


import six
# import inspect


# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


def loader_load_api_hook():
    """
        加载并返回 api_hook_list.py 中定义的 api_hook 列表

        @return: list : ApiHookBase 对象列表
    """
    ret = []
    from api_hook_def import ApiHookBase
    import api_hook_list
    for obj in six.itervalues(vars(api_hook_list)):
        # if inspect.isclass(obj):  # 换成 isobj
        if isinstance(obj, ApiHookBase):
            # print(obj)
            ret.append(obj)
    return ret


def loader_load_api_hook_config():
    """
        加载 api 配置

        @return: tuple : (api_config, api_global_config)
    """
    import api_hook_config
    api_hook_config.load_api_hook_config()
    return (api_hook_config.api_config, api_hook_config.api_global_config)


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    # 测试
    import pprint
    pprint.pprint(loader_load_api_hook())


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
