# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# # from __future__ import unicode_literals

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from _util.util import *
# from _util.msdn import msdn
from _util.base import *

from engine import defines
from engine.pydbg import PydbgEngine

import _dbg_config


# ---------------------------------------------------------------------------
# 函数 -


# ---------------------------------------------------------------------------
# 类定义


class HookContainer:
    """hook 容器. 主要是为了 reason"""
    def __init__(self):
        # 每个元素: addr: (callback, reason)
        self.hook_dict = {}

    def add_hook(self, addr, callback, reason=None):
        """添加 hook"""
        assert not self.has_hook(addr, reason=reason)
        if addr not in self.hook_dict:
            self.hook_dict[addr] = [(callback, reason)]
        else:
            self.hook_dict[addr].append((callback, reason))

    def del_hook(self, addr, reason=None):
        """
        删除 hook
        不能保证调用者已经确认存在 hook, 所以开头不要 assert
        """
        for index, item in enumerate(self.hook_dict[addr]):

            # 查找相同原因的删掉
            if reason == item[1]:
                del self.hook_dict[addr][index]

                # 删除之后如果此地址已没有 hook, 则删除此地址
                if len(self.hook_dict[addr]) == 0:
                    del self.hook_dict[addr]

                return True

        # 不存在 hook
        return False

    def has_hook(self, addr, reason=None):
        """检查是否有 hook"""
        if addr in self.hook_dict:
            for item in self.hook_dict[addr]:
                if reason == item[1]:
                    return True
        return False

    def has_any_hook(self, addr):
        """检查某个地址是否有任意 hook"""
        return addr in self.hook_dict and len(self.hook_dict[addr]) != 0

    def invoke_all_hook(self, addr, dbg, *args, **kargs):
        """
        调用某个地址所有 callback
        没有调用 "某1个" hook 的说法. 断点命中了, 命中的时候谁知道是因为哪个原因命中的呢??
        """
        assert self.has_any_hook(addr)
        for item in self.hook_dict[addr]:

            # 调用回调
            # 注意: 回调的第1个参数是断点地址, 第2个参数是 Debugger() 对象
            item[0](addr, dbg, args, kargs)

    def __len__(self):
        """所有 callback 的个数"""
        ret = 0
        for k, v in self.hook_dict.items():
            ret += len(v)
        return ret


class Debugger:
    """PydbgEngine 的 wrapper"""

    def __init__(self):

        _dbg_config.load_dbg_config()
        self.dbg_config = _dbg_config.dbg_config

        self.engine = PydbgEngine()
        self.engine.set_callback(defines.LOAD_DLL_DEBUG_EVENT, callback_func=self._callback_load_sys_dll)
        self.engine.set_callback(defines.EXIT_PROCESS_DEBUG_EVENT, callback_func=self._callback_process_exit)
        self.engine.set_callback(defines.EXCEPTION_DEBUG_EVENT, callback_func=self._callback_any_exception)

        # 被调试文件信息
        self.debugee_name = None
        self.debugee_md = None
        self.debugee_pe = None
        self.debugee_ep = None

        # api_hook/debugee_hook 信息
        self.api_hook_list = []
        self.debugee_hook_list = []
        self.callback_api_hook_hit = None
        self.callback_debugee_hook_hit = None
        self.callback_proc_exit_api = None
        self.callback_proc_exit_debugee = None

        # 其他 hook 信息

        # 运行的状态信息 - Hook
        self.hook_container = HookContainer()             # 所有 hook 的容器
        self.to_install_api_hook_dict = {}                # 整理 api_hook 列表为字典, 以模块名称为 key. 不为空表示还有需要设置的 api_hook
        self.installed_api_addr_to_api_hook_dict = {}     # api 地址到对应的 api_hook 对象的字典
        self.installed_addr_to_tid_hook_dict = {}         # 地址对应的 (callback, tid) 字典

        # 运行的状态信息
        self.is_debugee_loaded = False                    # 被调试模块是否加载. 一次性的
        self.is_debugee_ep_been_hit = False               # 被调试模块是否执行了入口点. 一次性的
        self.is_install_api_hook_start = False            # 是否开始安装 api_hook. 在模块加载回调中判断

        # 常量
        self.REASON_API_HOOK = "PYDBG_API_MONITOR"
        self.REASON_DEBUGEE_HOOK = "PYDBG_DEBUGEE_MONITOR"

    # ---------------------------------------------------------------------------
    # 启动之前设置 xx

    def set_hook_list(self, api_hook_list, debugee_hook_list):
        """设置 api_hook/debugee_hook 列表"""
        # api_hook 列表, 将其整理为以模块名称为 key 的 dict
        self.api_hook_list = api_hook_list

        for api_hook in api_hook_list:
            if api_hook.dll_name not in self.to_install_api_hook_dict:
                self.to_install_api_hook_dict[api_hook.dll_name] = [api_hook]
            else:
                self.to_install_api_hook_dict[api_hook.dll_name].append(api_hook)

        # debugee_hook 列表
        self.debugee_hook_list = debugee_hook_list

    def set_hook_hit_callback(self, callback_api_hook_hit, callback_debugee_hook_hit):
        """设置 api_hook/debugee_hook 命中后回调函数"""
        self.callback_api_hook_hit = callback_api_hook_hit
        self.callback_debugee_hook_hit = callback_debugee_hook_hit

    def set_proc_exit_callback(self, callback_proc_exit_api, callback_proc_exit_debugee):
        """设置进程退出后分别调用的 api_hook/debugee_hook 回调"""
        self.callback_proc_exit_api = callback_proc_exit_api
        self.callback_proc_exit_debugee = callback_proc_exit_debugee

    # ---------------------------------------------------------------------------
    # 启动

    def xuck_it(self, debugee_path, debugee_cmdline):
        """启动调试"""
        # 检查一些配置

        assert self.dbg_config["when_install_api_hook"]
        if self.dbg_config["when_install_api_hook"] in ["dll_load", "dll_ep"]:
            assert self.dbg_config["install_api_hook_opp_dll_name"] and len(self.dbg_config["install_api_hook_opp_dll_name"]) != 0
        elif self.dbg_config["when_install_api_hook"] == "addr_hit":
            assert self.dbg_config["install_api_hook_opp_hit_addr"]

        # 保存一些信息

        self.debugee_path = debugee_path
        self.debugee_cmdline = debugee_cmdline
        self.debugee_name = os.path.basename(debugee_path)

        # 加载并启动调试

        self.engine.load(debugee_path, command_line=debugee_cmdline)
        self.engine.run()

        # 完了之后进程就该结束了

    # ---------------------------------------------------------------------------
    # 调试事件回调 - 忽略参数, 使用 self.engine 访问调试器

    def _callback_load_sys_dll(self, *args, **kargs):
        """回调: 系统模块加载"""

        # 判断是否要设置 api_hook 开始安装标记
        if not self.is_install_api_hook_start:

            # 进程启动时安装 api_hook
            if self.dbg_config["when_install_api_hook"] == "proc_create":
                self.is_install_api_hook_start = True

            # 某个模块加载/调用入口时安装
            elif self.dbg_config["when_install_api_hook"] in ["dll_load", "dll_ep"]:
                new_dll_name = dbg.system_dlls[-1].name
                if new_dll_name == self.dbg_config["install_api_hook_opp_dll_name"]:
                    if self.dbg_config["when_install_api_hook"] == "dll_load":
                        self.is_install_api_hook_start = True
                    else:
                        # TODO
                        pass

        # 被调试模块 (exe/dll) 首次加载
        if not self.is_debugee_loaded and self.engine.check_has_module(self.debugee_name):

            # 这里是在有 "系统模块加载" 时进行判断, 有没有直接的 "被调试模块加载" 的回调呢???

            # 根据配置隐藏调试器
            if self.dbg_config["is_hide_debugger"]:
                self.engine.hide_debugger()

            # 解析入口点
            self.debugee_md = self.engine.get_md(self.debugee_name)
            self.debugee_pe = XPE(name=self.debugee_md.szExePath)
            self.debugee_ep = self.debugee_md.modBaseAddr + self.debugee_pe.get_ep_offset()

            # 如果被调试模块加载时就开始安装 api_hook
            if self.dbg_config["when_install_api_hook"] == "exe_load":

                # 设置标记. 在每个模块加载回调的末尾检查此标记
                self.is_install_api_hook_start = True

            elif self.dbg_config["when_install_api_hook"] == "exe_load":

                # 如果被调试模块入口调用之后才安装 api_hook, 则在模块入口下断, 在其回调中设置标记, 并安装 api_hook
                assert not self.is_debugee_ep_been_hit
                self.engine.bp_set(address=ep, handler=self._handler_debugee_ep_hit)

            # 安装 debugee_hook
            # TODO

            # 设置标记.
            self.is_debugee_loaded = True

        # 判断是否可以安装 api_hook 了
        if self.is_install_api_hook_start:
            self._check_install_api_hooks()

        # 返回
        return defines.DBG_CONTINUE

    def _callback_process_exit(self, *args, **kargs):
        """进程结束回调"""
        self._info("-" * 100)
        self._info(">>> debugee exit")
        self._info("-" * 100)

        # 调用 api_hook/debugee_hook 的回调
        self.callback_proc_exit_api(self)
        self.callback_proc_exit_debugee(self)

        return defines.DBG_CONTINUE

    def _callback_any_exception(self, *args, **kargs):
        """任意异常"""
        # ec = args[1]
        # self._info("debugee exception: 0x%X -> %s" % (ec, msdn.resolve_code_exception(ec)))
        return defines.DBG_CONTINUE

    # ---------------------------------------------------------------------------
    # 辅助设置的各种断点回调

    def _handler_debugee_ep_hit(self, *args, **kargs):
        """
            回调 - 被调试模块的入口点

            进入此回调的原因:
                - 要求在被调试模块入口调用时做些事情, 例如: 安装 api_hook
        """
        assert not self.is_debugee_ep_been_hit

        # 删除此入口断点
        self.engine.bp_del(self.engine.context.Eip)

        # 设置标记 - 入口点已调用
        self.is_debugee_ep_been_hit = True

        # 设置标记 - 可以在模块加载回调中判断安装 api_hook 了
        self.is_install_api_hook_start = True

        # 安装 api_hook
        self._check_install_api_hooks()

        return defines.DBG_CONTINUE

    def _handler_all_debugee_hook_proxy(self, *args, **kargs):
        """所有 debugee_hook 的回调"""
        pass

    def _handler_all_tid_hook_proxy(self, *args, **kargs):
        """所有按 tid 安装的 hook 的回调"""
        eip = args[0]
        assert eip in self.installed_addr_to_tid_hook_dict

        # 判断是不是我们想要的线程
        if self.cur_tid() == self.installed_addr_to_tid_hook_dict[eip][1]:
            self.installed_addr_to_tid_hook_dict[eip][0](self)

    def _handler_all_api_hook_proxy(self, *args, **kargs):
        """
        所有 api_hook 的回调. 获取对应的 api_hook, 然后交由 core 处理
        """
        eip = args[0]

        # 由参数 eip 获取对应的 api_hook
        api_hook = self.installed_api_addr_to_api_hook_dict[eip]

        # 调用回调
        self.callback_api_hook_hit(self, api_hook)

        # 返回
        return defines.DBG_CONTINUE

    def _handler_all_hook_proxy(self, *args, **kargs):
        """所有安装的 hook 都走这里"""
        # 由当前 eip 获取对应的 callback 列表

        eip = self.engine.context.Eip
        if not self.hook_container.has_any_hook(eip):

            # 不知为啥, 这里的 eip 是实际的 api_start-1. 所以手动修复一下

            eip = eip + 1
            if not self.hook_container.has_any_hook(eip):
                self._error(">>> invalid eip/eip+1, which does not exist in hook_container:")
                self._error(">>>     eip: %s" % self.engine.addr_resolve(eip))

                self._uninstall_hook_raw(eip)
                return defines.DBG_CONTINUE
            else:
                self._warn(">>> invalid eip, but valid eip+1: %s" % self.engine.addr_resolve(eip))

        try:
            # 调用所有的回调
            # 对于 GUI 调试器, 这里要挨个检查每个回调的返回值, 看是否需要暂停调试器
            # 但咱是 pydbg, m命令行的, 所以就不用了
            self.hook_container.invoke_all_hook(eip, self)
        except:
            pass

        # 返回
        return defines.DBG_CONTINUE

    # ---------------------------------------------------------------------------

    # hook

    def _install_hook_raw(self, addr, callback):
        """通过下断点安装 hook"""
        try:
            self.engine.bp_set(addr, handler=callback)
            return True

        except:
            self._warn("install hook(set bp) fail: %.8X" % (addr))
            return False

    def _uninstall_hook_raw(self, addr):
        """删除 hook 所在位置的断点"""
        try:
            self.engine.bp_del(addr)
        except:
            self._error("del bp fail: %s" % (self.engine.addr_resolve(addr)))

    def install_hook(self, addr, callback, reason=None):
        """
        安装 hook

        所有的 hook 安装都要走这条线
        如果已经安装了, 就再加1个处理程序就好了, 不要再去重复下断点了

        @return: bool : 安装成功还是失败
        """
        # 查看是否已在指定位置安装了 hook
        if self.hook_container.has_hook(addr, reason=reason):

            # 此位置+此原因的 hook 已安装
            return False

        elif self.hook_container.has_any_hook(addr):

            # 此位置 hook 已安装, 但此原因的未安装. 加入回调列表
            self.hook_container.add_hook(addr, callback, reason=reason)
            return True

        else:
            # 尝试安装 hook
            if self._install_hook_raw(addr, self._handler_all_hook_proxy):

                # 将下断位置原因和回调加入到列表中
                self.hook_container.add_hook(addr, callback, reason=reason)
                return True

            else:
                # 安装失败
                return False

    def uninstall_hook(self, addr, reason=None):
        """
        卸载已安装的 hook

        所有的 hook 下载都要走这条线
        """
        self.hook_container.del_hook(addr, reason=reason)

        # 此位置已无 hook, 删除断点
        if not self.hook_container.has_any_hook(addr):
            self._uninstall_hook_raw(addr)

    def has_installed_api_hook(self, api_name):
        """是否已安装某 api_hook"""
        for addr, api_hook in self.installed_api_addr_to_api_hook_dict.items():
            if api_name == api_hook.api_name:

                # 已安装
                assert self.hook_container.has_hook(addr, self.REASON_API_HOOK)
                return True

        # 未安装此 api_name 的 hook
        return False

    def _install_api_hook(self, api_hook):
        """在 api 位置设置软件断点, 并设置断点回调"""
        # 解析地址
        addr = self.engine.func_resolve(api_hook.dll_name, api_hook.api_name)
        if self.engine.is_address_valid(addr):

            # 安装 hook
            if self.install_hook(addr, self._handler_all_api_hook_proxy, self.REASON_API_HOOK):

                # 添加到 地址->api_hook 字典. 在回调中通过地址找到 api_hook, 调用其回调
                assert addr not in self.installed_api_addr_to_api_hook_dict
                self.installed_api_addr_to_api_hook_dict[addr] = api_hook

                # self._info("install api_hook success: %s" % api_hook)

            else:
                self._warn("install api hook fail: %s - %.8X" % (api_hook, addr))
        else:
            # 无效的地址
            self._error("resolve addr fail: %.8X -> %s" % (addr, api_hook))

    def uninstall_api_hook(self, api_name):
        """
        卸载 self.api_hook_list 中的 api_hook

        如果 hook 已安装, 则从 self.hook_container / self.installed_api_addr_to_api_hook_dict 中删除
        如果 hook 未安装, 则从 self.to_install_api_hook_dict
        """
        for addr, api_hook in self.installed_api_addr_to_api_hook_dict.items():
            if api_name == api_hook.api_name:

                assert self.hook_container.has_hook(addr, self.REASON_API_HOOK)
                self._info("uninstall api_hook: 0x%.8X -> %s" % (addr, self.installed_api_addr_to_api_hook_dict[addr]))

                self.uninstall_hook(addr, self.REASON_API_HOOK)
                del self.installed_api_addr_to_api_hook_dict[addr]

    def _install_debugee_hook(self, debugee_hook):
        """安装 debugee_hook """
        if self.install_hook(debugee_hook.addr, self._handler_all_debugee_hook_proxy, reason=self.REASON_DEBUGEE_HOOK):

            self._info("install debugee_hook: %s" % debugee_hook)
        else:
            self._error("install debugee_hook fail: %s" % debugee_hook)

    def uninstall_debugee_hook(self, addr):
        """卸载 debugee_hook"""
        pass

    def _check_install_api_hooks(self):
        """检查是否有需要安装但还没安装的 api_hook"""
        if len(self.to_install_api_hook_dict) != 0:

            # 因为 api_hook 安装方式不一定是每个系统模块加载后立即安装此模块的 api_hook
            # 有可能系统模块已加载但是 api_hook 还未安装
            # 所以这里要逐个判断系统模块是否包含未安装的 api_hook, 而不是只判断最新加载的那个模块

            for dll_name, api_hook_list_in_dll in self.to_install_api_hook_dict.items():

                if self.engine.check_has_system_dll(dll_name):

                    # 逐个安装此模块的 api_hook
                    for api_hook in api_hook_list_in_dll:
                        self._install_api_hook(api_hook)

                    # 删除此模块, 表示已安装
                    del self.to_install_api_hook_dict[dll_name]

    def set_install_api_hook_start(self):
        """当调试器配置的 when_install_api_hook 为 dynamic 时, 代码手动调用此函数 """
        self._check_install_api_hooks()
        self.is_install_api_hook_start = True

    def notify_api_hit_raw(self, api_hit_raw):
        """api_hook 处理的结果"""
        if api_hit_raw.is_pass:
            print(api_hit_raw)

    def notify_deubgee_hit_raw(self):
        """"""
        pass

    # 其他

    def install_hook_by_tid(self, addr, callback):
        """按照线程在指定地址安装 hook. 不是此线程的则不调用回调"""
        if self.engine.is_address_valid(addr):
            if self.install_hook(addr, self._handler_all_tid_hook_proxy, self.REASON_TID()):

                # 安装成功. 加入到列表
                assert addr not in self.installed_addr_to_tid_hook_dict
                self.installed_addr_to_tid_hook_dict[addr] = (callback, self.cur_tid())

                self._info("install hook by tid at addr: %s" % self.engine.addr_resolve(addr))

            else:
                # 安装失败
                self._error("install tid hook at addr failed: %s" % self.engine.addr_resolve(addr))
        else:
            # 无效的地址
            self._error("invalid addr to install hook for cur tid: %s" % self.engine.addr_resolve(addr))

    def uninstall_hook_by_tid(self, addr):
        """卸载某地址+当前线程的 hook"""
        if addr in self.installed_addr_to_tid_hook_dict and self.cur_tid() == self.installed_addr_to_tid_hook_dict[addr][1]:

            # 卸载+删除
            self.uninstall_hook(addr, self.REASON_TID())
            del self.installed_addr_to_tid_hook_dict[addr]

            self._info("unisntall tid hook at addr: %s" % self.engine.addr_resolve(addr))

    def get_call_stack_raw(self, max_depth=None, is_fix_api_start=False):
        return self.engine.get_call_stack_raw(max_depth=max_depth, is_fix_api_start=is_fix_api_start)

    def cur_tid(self):
        return self.engine.dbg_evt.dwThreadId

    def cur_eip(self):
        return self.engine.context.Eip

    def info(self, file, msg):
        print("[PYDBG-INFO ] - %s" % msg)

    def warn(self, file, msg):
        print("[PYDBG-WARN ] - %s" % msg)

    def error(self, file, msg):
        print("[PYDBG-ERROR] - %s" % msg)

    # ---------------------------------------------------------------------------
    # 日志

    def _info(self, msg):
        self.info(__file__, msg)

    def _warn(self, msg):
        self.warn(__file__, msg)

    def _error(self, msg):
        self.error(__file__, msg)

    # ---------------------------------------------------------------------------
    # 读写进程内存

    def get_esp(self):
        return self.engine.get_esp()

    def read(self, addr, len_):
        return self.engine.read(addr, len_)

    def write(self, addr, data, len_=0):
        return self.write(addr, data, length=len_)

    # ---------------------------------------------------------------------------
    # 其他

    def REASON_TID(self):
        return "PYDBG_HOOK_REASON_TID_%X" % self.cur_tid()

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------


if __name__ == "__main__":
    c = HookContainer()
    print(12 in c)


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
