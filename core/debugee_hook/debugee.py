# -*- coding: utf-8 -*-

"""
debugee related thing
"""
import os
import inspect
from collections import OrderedDict

import log
import util
import defines

file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))

# ---------------------------------------------------------------------------
# global - load from .txt file

#
# func addrs
# a dict:
#    {start: (start, end, name),
#    {start: (start, end, name)},
#     ...}
#
global v_tmp_func_list
v_tmp_func_list = None

# exclude func address
# global v_tmp_exclude_func_address
v_tmp_exclude_func_address = None

# eclude func names
# global v_tmp_exclude_func_name
v_tmp_exclude_func_name = None

# debugee patches
# global v_tmp_debugee_patches
v_tmp_debugee_patches = None

# nop ranges
# global v_tmp_debugee_nop_ranges
# [(start, end), (start, end), ...]
v_tmp_debugee_nop_ranges = None

# func call cnt max, print it, add to code to "exclude"
# at least 100
# global v_tmp_func_cnt_max_when_pt
v_tmp_func_cnt_max_when_pt = None

# func call cnt max, runtime. when max reached, no longer invoke this anymore.
v_tmp_func_cnt_max_runtime = None

# is install debugee patches
v_tmp_is_install_debugee_patches = False

# is install debugee hooks
v_tmp_is_isntall_debugee_hooks = False

# is install debugee func start bps
v_tmp_is_install_debugee_func_starts = False

# is pt func tree when process exit
v_tmp_is_pt_func_tree_when_process_exit = False

# is pt func cnt when process exit
v_tmp_is_pt_func_cnt_when_process_exit = False

# is pt func invoke
v_tmp_is_pt_func_invoke = False


# ---------------------------------------------------------------------------

# func call record
# global v_tmp_func_record
v_tmp_func_record = []

# global v_tmp_func_cnt_runtime
# dict: {func1: 1, func2: 4, ...}
v_tmp_func_cnt_runtime = {}


# ---------------------------------------------------------------------------

def _pt_log(line):
    """
        proxy to log.pt_log()
    """
    log.pt_log(line)


# ---------------------------------------------------------------------------
# load

def load_debugee_func_list():
    """
    """
    target_txt_file = util.gen_path_tail_debugee("_ida_funcs.txt", has_ext=False)

    if os.path.exists(target_txt_file):

        global v_tmp_func_list
        assert v_tmp_func_list is None

        try:
            file = open(target_txt_file, "r")
        except:
            _pt_log("open file exception: %s" % target_txt_file)
        else:
            _pt_log("loading func address from file: %s" % target_txt_file)

            global v_tmp_exclude_func_name
            global v_tmp_exclude_func_address

            v_tmp_func_list = {}
            for line in file:

                assert line.count(" ") == 2
                splits = line.split(" ")
                assert len(splits) == 3

                start = int(splits[0], 16)
                assert start not in v_tmp_func_list
                name = splits[2].strip("\n")
                if start not in v_tmp_exclude_func_address and name not in v_tmp_exclude_func_name:
                    # offset format: HEX
                    v_tmp_func_list[start] = (start, int(splits[1], 16), name)

            file.close()

    else:
        _pt_log(">>> func addrs file not exist: %s" % target_txt_file)


# ---------------------------------------------------------------------------
# func tree


class func_tree_node:

    def __init__(self, eip, to_addr):
        """
            @param: eip     : int : func start address
            @param: to_addr : int : call return to address
        """
        self.func_start = eip
        self.to_addr = to_addr

        global v_tmp_func_list
        assert self.func_start in v_tmp_func_list

        self.func_end = v_tmp_func_list[self.func_start][1]
        self.func_name = v_tmp_func_list[self.func_start][2]

        self.sub_nodes = []  # a list of func_tree_node() objects

    def get_to_addr_accept_ranges(self):
        """
            get code ranges that can be added to this node, includint sub_nodes

            @return: list : a list of tuple, representing code ranges.
        """
        ret = [(self.func_start, self.func_end)]

        if len(self.sub_nodes) != 0:

            for range_ in self.sub_nodes[-1].get_to_addr_accept_ranges():

                has_ = False
                for has_item in ret:
                    if has_item[0] == range_[0]:
                        assert has_item[1] == range_[1]
                        has_ = True
                        break
                if not has_:
                    ret.append(range_)

        return ret

    def check_can_tail_to_addr(self, to_addr):
        """
            check if to_addr can be added to this node, or sub_nodes

            @return: bool :
        """
        ranges = self.get_to_addr_accept_ranges()
        for range_ in ranges:
            if range_[0] <= to_addr and to_addr <= range_[1]:
                return True
        return False

    def add_tail_node(self, eip, to_addr):
        """
            add tail node when self.check_can_tail_to_addr() return True.
            this must success

            @return: None :
            @raise:
        """
        if len(self.sub_nodes) == 0:

            # as first sub node
            assert self.func_start <= to_addr and to_addr <= self.func_end
            self.sub_nodes.append(func_tree_node(eip, to_addr))

        else:
            if self.sub_nodes[-1].check_can_tail_to_addr(to_addr):

                # pass to last sub_node
                self.sub_nodes[-1].add_tail_node(eip, to_addr)

            else:

                # add to existing sub_nodes
                assert self.func_start <= to_addr and to_addr <= self.func_end
                self.sub_nodes.append(func_tree_node(eip, to_addr))

    def get_node_cnt(self):
        """
            @return: int :
        """
        ret = 1
        for sub_node in self.sub_nodes:
            ret = ret + sub_node.get_node_cnt()
        return ret

    def is_same_node(self, node1):
        """
            check if the other node is same with this one

            !+ when we mark some node as "un-important", all same node shall be marked too.
            !+ we can also mark some func as "un-important", then all nodes with that func as root shall be marked too.
        """
        pass

    def __str__(self):
        """
            str desc
        """
        return "%.8X(%.8X-%.8X)(%d-%s)" % (self.to_addr, self.func_start, self.func_end, self.get_node_cnt(), self.func_name)

    def lines(self):
        """
            @return: list : a list of string
        """
        lines = [str(self)]
        for sub_node in self.sub_nodes:
            for line in sub_node.lines():
                lines.append("    %s" % line)
        return lines


def _parse_debugee_func_tree(dbg):
    """
        @return: dict : each item: {tid: [func_tree_node(), func_tree_node(), ...],
                                    tid: [func_tree_node(), ...],
                                    ...}
    """
    tid_to_func_node_dict = {}

    global v_tmp_func_record
    for record in v_tmp_func_record:

        tid = record[0]
        func_start = record[1]
        to_addr = record[2]

        if tid not in tid_to_func_node_dict:

            # first tree of this tid
            tid_to_func_node_dict[tid] = [func_tree_node(func_start, to_addr)]

        else:
            is_tailed = False
            root_node_list = tid_to_func_node_dict[tid]

            for i in range(len(root_node_list))[::-1]:

                root_node = root_node_list[i]
                if not root_node.check_can_tail_to_addr(to_addr):
                    continue
                else:
                    root_node.add_tail_node(func_start, to_addr)
                    is_tailed = True
                    break

            if not is_tailed:
                # this is quite common, for example:
                #     DialogBoxParamW(v3, L"STARTDLG", 0, sub_40D4DE, 0);
                # sub_40D4DE will always be some "root_node"
                tid_to_func_node_dict[tid].append(func_tree_node(func_start, to_addr))

    return tid_to_func_node_dict


def _pt_debugee_func_tree(dbg):
    """
        parse func address and print result
    """
    tid_to_func_node_dict = _parse_debugee_func_tree(dbg)
    for (tid, root_node_list) in tid_to_func_node_dict.items():

        _pt_log(">>> tid: %d" % tid)
        _pt_log(">>> func tree cnt: %d" % len(root_node_list))

        for root_node in root_node_list:

            _pt_log(">>> root node: %s" % root_node)
            for line in root_node.lines():
                _pt_log("       %s" % line)
            _pt_log("")

        _pt_log("")


# ---------------------------------------------------------------------------
# func count

def _parse_debugee_func_cnt(dbg):
    """
        @return: dict : like this: {func1: (17, [tid1, tid2, ...], [to_addr1, to_addr2, ...]),
                                    func2: (23, [tid1, tid2, ...], [to_addr1, to_addr2, ...]),
                                    ...}
    """
    # like this: {func1: 1),
    #             func2: 2),
    #             ...}
    #             number represents func call cnt
    func_to_cnt_dict = {}
    # like this: {func1: ([tid1, tid2, tid3, ...], [to_addr1, to_addr2, ...]),
    #             func2: ([tid1, tid2, tid3, ...], [to_addr1, to_addr2, ...]),
    #             ...}
    func_to_xx_dict = {}

    global v_tmp_func_list
    global v_tmp_func_record
    for record in v_tmp_func_record:

        tid = record[0]
        func_start = record[1]
        to_addr = record[2]

        assert func_start in v_tmp_func_list

        if func_start not in func_to_cnt_dict:
            func_to_cnt_dict[func_start] = 1
        else:
            func_to_cnt_dict[func_start] = func_to_cnt_dict[func_start] + 1

        if func_start not in func_to_xx_dict:
            func_to_xx_dict[func_start] = ([tid], [to_addr])
        else:
            if tid not in func_to_xx_dict[func_start][0]:
                func_to_xx_dict[func_start][0].append(tid)
            if to_addr not in func_to_xx_dict[func_start][1]:
                func_to_xx_dict[func_start][1].append(to_addr)

    # sort by call cnt, then combine 2 dicts
    ret = OrderedDict()
    sorted_func_starts = sorted(func_to_cnt_dict, key=func_to_cnt_dict.__getitem__)
    for func_start in sorted_func_starts:
        ret[func_start] = (func_to_cnt_dict[func_start], func_to_xx_dict[func_start][0], func_to_xx_dict[func_start][1])
    return ret


def _pt_debugee_func_cnt(dbg):
    """
        print func call count
    """
    # like this: {func1: (17, [tid1, tid2, ...], [to_addr1, to_addr2, ...]),
    #             func2: (23, [tid1, tid2, ...], [to_addr1, to_addr2, ...]),
    #             ...}
    func_cnt_dict = _parse_debugee_func_cnt(dbg)

    if func_cnt_dict is not None and len(func_cnt_dict) != 0:

        _pt_log("-" * 100)
        _pt_log("total invoke func cnt: %d" % len(func_cnt_dict))

        global v_tmp_func_list
        for (func_start, xx) in func_cnt_dict.items():
            _pt_log("    func: %.8X, call_cnt: %d, tid_cnt: %d, to_addr_cnt: %d, name: %s" % (func_start, xx[0], len(xx[1]), len(xx[2]), v_tmp_func_list[func_start][2]))
        _pt_log("-" * 100)
        _pt_log("")

        global v_tmp_func_cnt_max_when_pt
        assert v_tmp_func_cnt_max_when_pt is not None and v_tmp_func_cnt_max_when_pt >= 100
        func_starts_str = ""
        for (func_start, xx) in func_cnt_dict.items():
            if xx[0] > v_tmp_func_cnt_max_when_pt:
                func_starts_str = func_starts_str + ", 0x%.8X" % func_start

        if func_starts_str != "":
            _pt_log("-" * 100)
            _pt_log("func starts that invoke more than %d times:" % v_tmp_func_cnt_max_when_pt)
            _pt_log("    %s" % func_starts_str)
            _pt_log("-" * 100)


# ---------------------------------------------------------------------------
# handler

def handler_FuncStart(dbg):
    """
        add func record to v_tmp_func_record
    """
    eip = dbg.context.Eip
    # func_item = v_tmp_func_list[eip]
    # _pt_log(">>> %.8X --> (%.8X %.8X %s)" % (eip, func_item[0], func_item[1], func_item[2]))

    # ---------------------------------------------------------------------------
    # u're suggested to run this snippet first, to check if there's any "to_addr" that belong to no function.
    # if there is, we can't build func tree
    # ---------------------------------------------------------------------------
    # is_find = False
    to_addr = dbg.read_stack_int32(0)
    # for (start, func_item) in v_tmp_func_list.items():
    #     if start <= to_addr and to_addr <= func_item[1]:
    #         _pt_log(">>> %.8X called from %.8X(%s)" % (eip, func_item[0], func_item[2]))
    #         is_find = True
    # if not is_find:
    #     _pt_log(">>> %.8X is new thread start?(%.8X)" % (eip, to_addr))

    # add record
    global v_tmp_func_record
    v_tmp_func_record.append((dbg.dbg.dwThreadId, eip, to_addr))

    # assert
    global v_tmp_func_list
    assert eip in v_tmp_func_list

    # pt
    global v_tmp_is_pt_func_invoke
    if v_tmp_is_pt_func_invoke:
        _pt_log(">>> debugee func: %.8X - %s" % (eip, v_tmp_func_list[eip][2]))

    # check func cnt max
    global v_tmp_func_cnt_runtime
    if eip not in v_tmp_func_cnt_runtime:
        v_tmp_func_cnt_runtime[eip] = 1
    else:
        v_tmp_func_cnt_runtime[eip] = v_tmp_func_cnt_runtime[eip] + 1
        # del bp maybe
        global v_tmp_func_cnt_max_runtime
        if v_tmp_func_cnt_runtime[eip] > v_tmp_func_cnt_max_runtime:
            dbg.bp_del(eip)
            _pt_log(">>> del func start bp because func invoke cnt reach max: %d" % (v_tmp_func_cnt_max_runtime))

    # ret
    return defines.DBG_CONTINUE


# ---------------------------------------------------------------------------
# install

def install_debugee_func_starts(dbg, debugee_base):
    """
        set bp at all func starts
    """
    global v_tmp_is_install_debugee_func_starts
    if v_tmp_is_install_debugee_func_starts:

        global v_tmp_func_list
        if v_tmp_func_list is not None and len(v_tmp_func_list) != 0:

            _pt_log(">>> bp debugee func starts....")

            for (start, func_item) in v_tmp_func_list.items():

                # _pt_log("set debugee func bp at %.8X" % func)
                dbg.bp_set(address=start, handler=handler_FuncStart)

            _pt_log(">>> func starts to bp: %d" % len(v_tmp_func_list))


def install_debugee_patches(dbg, debugee_base):
    """
        load patches
    """
    global v_tmp_is_install_debugee_patches
    if v_tmp_is_install_debugee_patches:

        # install patch
        global v_tmp_debugee_patches
        if v_tmp_debugee_patches is not None and len(v_tmp_debugee_patches) != 0:
            #
            _pt_log(">>> patching debugee....")

            pass

        # install nope
        global v_tmp_debugee_nop_ranges
        if v_tmp_debugee_nop_ranges is not None and len(v_tmp_debugee_nop_ranges) != 0:

            _pt_log(">>> noping debugee....")

            for range_ in v_tmp_debugee_nop_ranges:

                start = range_[0]
                len_ = range_[1] - range_[0]
                data = b'\x90' * len_

                _pt_log(">>> nop debugee from %.8X to %.8X, len: %X" % (range_[1], range_[0], len(data)))

                dbg.write(start, data, len_)


def install_debugee_hooks(dbg, debugee_base):
    """
    """
    global v_tmp_is_isntall_debugee_hooks
    if v_tmp_is_isntall_debugee_hooks:

        try:
            _pt_log(">>> install debugee hooks....")
            # z_tmp_debugee_hooks: dict: {offset1: handler_func1, offset2: handler_func2, ...}
            from z_1111 import z_tmp_debugee_hooks

            # for (offset, handler) in z_tmp_debugee_hooks.items():
            #     dbg.bp_set(debugee_base + offset, handler=handler)
            #     _pt_log(">>> install debugee hook at: %.8X" % (debugee_base + offset))

            for (addr, handler) in z_tmp_debugee_hooks.items():
                dbg.bp_set(addr, handler=handler)
                _pt_log(">>> install debugee hook at: %.8X" % (addr))

        except:
            _pt_log(">>> import z_1111.py failed, no debugee hooks to install...")


# ---------------------------------------------------------------------------
# callback

def callback_process_exit_pt_func_tree(dbg):
    """
    """
    global v_tmp_is_pt_func_tree_when_process_exit
    if v_tmp_is_pt_func_tree_when_process_exit:
        _pt_debugee_func_tree(dbg)


def callback_process_exit_pt_func_cnt(dbg):
    """
    """
    global v_tmp_is_pt_func_cnt_when_process_exit
    if v_tmp_is_pt_func_cnt_when_process_exit:
        _pt_debugee_func_cnt(dbg)


# ---------------------------------------------------------------------------
# common handler

def handler_walk_n_bytes(dbg):
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
