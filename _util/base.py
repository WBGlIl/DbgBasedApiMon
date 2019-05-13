# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals

import collections

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


class TransformedDict(collections.MutableMapping):
    """A dictionary that applies an arbitrary key-altering
       function before accessing the keys"""

    def __init__(self, *args, **kwargs):
        self.store = dict()
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __keytransform__(self, key):
        return key

    def __getitem__(self, key):
        return self.store[self.__keytransform__(key)]

    def __setitem__(self, key, value):
        self.store[self.__keytransform__(key)] = value

    def __delitem__(self, key):
        del self.store[self.__keytransform__(key)]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def __str__(self):
        return self.store.__str__()

    def __repr__(self):
        return self.store.__repr__()


class ConfigItemContainer(TransformedDict):

    def __init__(self, items=None):
        """
        @param: items : list : 列表. 元素类型: tuple : (key, value, desc)

        转化为的字典类型: {key: (value, desc)}
        """
        TransformedDict.__init__(self)
        if items:
            for item in items:
                self.store[item[0]] = (item[1], item[2])

    def purify(self):
        """把 key: (value, desc) 中的 desc 去掉"""
        ret = {}
        for k, v in self.store.items():
            ret[k] = v[0]
        return ret

    def original(self):
        """原始数据"""
        return self.store

    def replace_by(self, other):
        """用另一个对象的内容 "替换" 此对象的内容"""
        self.store = other.store

    def update_by(self, other):
        """
        用另一个对象的内容 "更新" 此对象的内容

        @return: bool : 是否进行了更新
        """
        ret = False
        for k, v in self.items():
            if k in other and self[k] != other[k]:
                self[k] = other[k]
                ret = True
        return ret

    def update_by_purified_dict(self, store_):
        """
        用1个 purified 字典来更新此数据

        @return: bool : 是否进行了更新
        """
        ret = False
        for k, v in self.items():
            if k in store_ and self[k] != store_[k]:
                self[k] = store_[k]
                ret = True
        return ret

    def __getitem__(self, key):
        """返回 (value, desc) 中的 value"""
        k = self.__keytransform__(key)
        return self.store[k][0]

    def __setitem__(self, key, value):
        """设置 (value, desc) 中的 value"""
        k = self.__keytransform__(key)
        v = self.store[k]
        self.store[k] = (value, v[1])

    def __delitem__(self, key):
        """不准许删除配置"""
        raise Exception("we do not allow delete config item")

    def __iter__(self):
        """遍历, 把 key: (value, desc) 中的 desc 去掉"""
        return iter(self.purify())

    def __str__(self):
        return self.purify().__str__()

    def __repr__(self):
        return self.purify().__repr__()


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    c = ConfigItemContainer([
        ("a", 1, "测试a"),
        ("b", True, """测试b\n呵呵, 我是不是很长啊..."""),
        ("c", None, "测试c"),
    ])
    print("c" in c)
    print("d" in c)
    import pprint
    pprint.pprint(c)
    c["a"] = "新A了哦"
    pprint.pprint(c)


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
