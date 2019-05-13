# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# # from __future__ import unicode_literals

# import os
# import sys
# sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


# ---------------------------------------------------------------------------
# main

import sys
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from _gui import Ui_MainWindow
from _gui_util import *


class MyWindow(QMainWindow, Ui_MainWindow):

    def __init__(self):
        super(MyWindow, self).__init__()
        self.setupUi(self)

        self.dbg_config_container = None
        self.api_global_config_container = None
        self.api_config = None
        self.api_select_config_container = None

        self.dbg_config_widgets_dict = {}
        self.api_global_config_widgets_dict = {}
        self.api_config_widgets_dict = {}
        self.api_select_config_widgets_dict = {}

    # ---------------------------------------------------------------------------

    def init_dbg_config(self, dbg_config_container):
        """根据 dbg 配置, 生成 UI 元素"""
        self.dbg_config_container = dbg_config_container

        widget, self.dbg_config_widgets_dict = config_contaienr_to_widget_and_dict(self.dbg_config_container)
        self.scroll_debugger_config.setWidget(widget)

    def init_api_global_config(self, api_global_config_container):
        """根据 api_hook 全局配置, 生成 UI 元素"""
        self.api_global_config_container = api_global_config_container

        widget, self.api_global_config_widgets_dict = config_contaienr_to_widget_and_dict(self.api_global_config_container)
        self.scroll_api_global_config.setWidget(widget)

    def init_api_config(self, api_config):
        """根据 api_hook 每个 api 的配置, 生成 UI 元素"""
        self.api_config = api_config

        widget, self.api_config_widgets_dict = api_config_to_widget_and_dict(self.api_config)
        self.scroll_api_config.setWidget(widget)

    def init_api_select_config(self, api_select_config_container):
        """选择 api 的配置, 生成 UI 元素"""
        self.api_select_config_container = api_select_config_container

        widget, self.api_select_config_widgets_dict = config_contaienr_to_widget_and_dict(self.api_select_config_container)
        self.scroll_api_select_config.setWidget(widget)

    # ---------------------------------------------------------------------------

    def btn_OK_click(self):
        """关闭窗口, 开始调试会话"""
        self.btn_Apply_clicked()
        self.close()
        # from loader import main
        # main()

    def btn_Cancel_clicked(self):
        """关闭窗口"""
        self.close()

    def btn_Apply_clicked(self):
        """应用配置"""

        # 调试器配置
        dbg_config_dict = widgets_dict_to_config_container_dict(self.dbg_config_widgets_dict)
        if self.dbg_config_container.update_by_purified_dict(dbg_config_dict):
            print("dbg config changed")
            _dbg_config.save_dbg_config(self.dbg_config_container.purify())
        else:
            print("dbg config not changed")

        # api_global_config
        api_global_config_dict = widgets_dict_to_config_container_dict(self.api_global_config_widgets_dict)
        if self.api_global_config_container.update_by_purified_dict(api_global_config_dict):
            print("api_global_config changed")
            api_hook_config.save_api_hook_config(api_global_config_new=self.api_global_config_container.purify())
        else:
            print("api_global_config not changed")

        # api_config
        api_config_dict = widgets_dict_to_api_config_dict(self.api_config_widgets_dict)
        is_changed = False
        for api_name, config_dict_new in api_config_dict.items():
            config_dict_old = self.api_config[api_name]
            for k, v in config_dict_new.items():
                if v != config_dict_old[k]:
                    config_dict_old[k] = v
                    is_changed = True
        if is_changed:
            print("api config changed")
            api_hook_config.save_api_hook_config(api_config_new=self.api_config)
        else:
            print("api config not changed")

        # api_select_config
        api_select_config_dict = widgets_dict_to_config_container_dict(self.api_select_config_widgets_dict)
        if self.api_select_config_container.update_by_purified_dict(api_select_config_dict):
            print("api_select_config updated")
            api_hook_select_config.save_api_hook_select_config(self.api_select_config_container.purify())
        else:
            print("api_select_config not updated")

        # debugee_config

    def chk_disable_api_mon_statchanged(self, state):
        pass

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


if __name__ == '__main__':

    app = QApplication(sys.argv)

    w = MyWindow()

    # dbg_config
    from pydbg import _dbg_config
    _dbg_config.load_dbg_config()
    w.init_dbg_config(_dbg_config.dbg_config)

    # api_global_config 与 api_config
    from core.api_hook import api_hook_config
    from core.api_hook import api_hook_select_config
    api_hook_config.load_api_hook_config()
    api_hook_select_config.load_api_hook_select_config()
    w.init_api_global_config(api_hook_config.api_global_config)
    w.init_api_config(api_hook_config.api_config)
    w.init_api_select_config(api_hook_select_config.api_hook_select_config)

    w.show()

    sys.exit(app.exec_())


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
