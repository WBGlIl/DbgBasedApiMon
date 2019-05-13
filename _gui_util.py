# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# # from __future__ import unicode_literals

from PyQt5.QtWidgets import *

# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


def config_contaienr_to_widget_and_dict(config_container):
    """
    将 ConfigItemContainer() 对象转换为界面显示的 widget

    @return: tuple : (widget, k_to_widgets_dict).
           :       : 其中 k_to_widgets_dict 为字典, 内容为: config_name: (widget, type(config_value))
    """
    vlayout = QVBoxLayout()
    widget = QWidget()
    widget.setLayout(vlayout)
    widgets_dict = {}

    # 生成并添加 UI 元素
    for k, v in config_container.original().items():

        value = v[0]
        desc = v[1]

        layout_detail = QVBoxLayout()

        if isinstance(value, bool):

            chk = QCheckBox(desc)
            chk.setChecked(value)

            layout_detail.addWidget(chk)

            widgets_dict[k] = (chk, bool)

        elif isinstance(value, int):

            edit = QLineEdit(str(value))

            layout_detail.addWidget(edit)
            layout_detail.addWidget(QLabel(desc))

            widgets_dict[k] = (edit, int)

        elif isinstance(value, str) or isinstance(value, unicode):

            edit = QLineEdit(value)

            layout_detail.addWidget(edit)
            layout_detail.addWidget(QLabel(desc))

            widgets_dict[k] = (edit, str)

        elif isinstance(value, list):

            edit = QLineEdit("".join("%s; " % v for v in value))

            layout_detail.addWidget(edit)
            layout_detail.addWidget(QLabel(desc))

            widgets_dict[k] = (edit, list)

        elif not value:
            #
            raise Exception("config value shall not be None. k is: %s" % k)

        else:
            raise Exception("unsupported config value type: %s:%s(%s)" % (k, value, type(value)))

        if isinstance(layout_detail, QVBoxLayout):
            layout_detail.addWidget(QLabel("- " * 50))

        vlayout.addLayout(layout_detail)

    return (widget, widgets_dict)


def widgets_dict_to_config_container_dict(widgets_dict):
    """将 widgets_dict 还原为 dict/json 格式的配置"""
    ret = {}
    for k, v in widgets_dict.items():
        widget = v[0]
        value_type = v[1]

        value = None
        if value_type == bool:
            value = widget.isChecked()

        elif value_type == int:
            try:
                value = int(widget.text())
            except:
                print("invalid value for k: %s - %s" % (k, widget.text()))

        elif value_type == str or value_type == unicode:
            value = widget.text()

        elif value_type == list:
            # 用 ";" 分割
            splits = widget.text().split(";")
            value = []
            for v in splits:
                if len(v) != 0:
                    value.append(v)

        else:
            raise Exception("not possible")

        # 这里判断是否为 None, 因为有可能为 False 值
        assert value is not None
        ret[k] = value

    return ret


def api_config_to_widget_and_dict(api_config):
    """
    将 api_config 转变为 widget 和 api_name:(widget,api_config_item) 的字典

    @param: api_config : dict : api_name:api_config_item 的字典
    """
    vlayout = QVBoxLayout()
    widget = QWidget()
    widget.setLayout(vlayout)
    widgets_dict = {}

    # 分组, (TODO:组内按 weiget 排序)
    groups = {}
    for k, v in api_config.items():
        group_name = v["group_name"]
        if group_name in groups:
            groups[group_name][k] = v
        else:
            groups[group_name] = {}
            groups[group_name][k] = v

    for group_name, group_item_dict in groups.items():

        g = QGroupBox(group_name)
        vlayout_group = QVBoxLayout()

        for api_name, config_dict in group_item_dict.items():

            hlayout_api = QHBoxLayout()
            config_widgets_dict = {}

            chk_is_enable = QCheckBox()
            chk_is_enable.setChecked(config_dict["is_enabled"])
            hlayout_api.addWidget(chk_is_enable)
            config_widgets_dict["is_enabled"] = (chk_is_enable, bool)

            # hlayout_api.addWidget(QLabel(config_dict["dll_name"]))
            name_label = QLabel(api_name)
            name_label.setFixedWidth(150)
            hlayout_api.addWidget(name_label)
            # hlayout_api.addWidget(QLabel(group_name))

            hlayout_api.addWidget(QLabel("重量:"))
            edit_weight = QLineEdit(str(config_dict["weight"]))
            hlayout_api.addWidget(edit_weight)
            config_widgets_dict["weight"] = (edit_weight, int)

            hlayout_api.addWidget(QLabel("最大调用次数:"))
            edit_max_invoke_cnt = QLineEdit(str(config_dict["max_invoke_cnt_runtime"]))
            hlayout_api.addWidget(edit_max_invoke_cnt)
            config_widgets_dict["max_invoke_cnt_runtime"] = (edit_max_invoke_cnt, int)

            chk_is_fragile = QCheckBox("是否容易导致程序崩溃")
            chk_is_fragile.setChecked(config_dict["is_fragile"])
            hlayout_api.addWidget(chk_is_fragile)
            config_widgets_dict["is_fragile"] = (chk_is_fragile, bool)

            chk_is_too_frequent = QCheckBox("是否可能被频繁调用")
            chk_is_too_frequent.setChecked(config_dict["is_too_frequent"])
            hlayout_api.addWidget(chk_is_too_frequent)
            config_widgets_dict["is_too_frequent"] = (chk_is_too_frequent, bool)

            widgets_dict[api_name] = config_widgets_dict
            vlayout_group.addLayout(hlayout_api)

        g.setLayout(vlayout_group)
        vlayout.addWidget(g)

    return (widget, widgets_dict)


def widgets_dict_to_api_config_dict(widgets_dict):
    """将 widgets_dict 转变为 api_name:api_config 字典, 其中的 api_config 是阉割过的, 只有非固定值, 用户可编辑的那些"""
    ret = {}

    for api_name, config_widgets_dict in widgets_dict.items():

        config_dict = {}

        config_dict["is_enabled"] = config_widgets_dict["is_enabled"][0].isChecked()
        config_dict["weight"] = str(config_widgets_dict["weight"][0].text())
        config_dict["max_invoke_cnt_runtime"] = str(config_widgets_dict["max_invoke_cnt_runtime"][0].text())
        config_dict["is_fragile"] = config_widgets_dict["is_fragile"][0].isChecked()
        config_dict["is_too_frequent"] = config_widgets_dict["is_too_frequent"][0].isChecked()

        ret[api_name] = config_dict

    return ret


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    g = QGroupBox()
    v = QVBoxLayout()
    v.addWidget(g)


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
