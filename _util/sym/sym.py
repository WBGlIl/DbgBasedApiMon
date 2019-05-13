# -*- coding: utf-8 -*-

"""
!+ 去他奶奶的dbghelp.SymXXX()，既然系统是固定的，咱自己解析sym!
文件格式:
kernel32.dll.txt:
    0000AA5C 0000AA8D lstrcmpW
    00061B7D 00061BAD GetProcessId
    ...
ntdll.dll.txt
    0006FBD2 0006FBDF _tolower
    ...
"""

import os
import inspect


file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))


# ---------------------------------------------------------------------------

def _pt_log(line):
    """
        proxy to log.pt_log()
    """
    log.pt_log(line)


# ---------------------------------------------------------------------------
# self-parsed symbol

#
# structure of v_tmp_symbols:
#   {"kernel32.dll": [(0x0000AA5C, 0x0000AA8D, lstrcmpW),
#                     (0x00061B7D, 0x00061BAD, GetProcessId),
#                     ...],
#    "ntdll.dll": [(0x0006FBD2, 0x0006FBDF, _tolower),
#                  ...]}
#
global v_tmp_symbols
v_tmp_symbols = {}


def _syms_load(sym_name, file_path):
    """
        load self-parsed symbol from specified file path

        @param: sym_name  : string : module name of symbols
        @param: file_path : string : symbol file path
    """
    assert os.path.exists(file_path)

    global v_tmp_symbols
    assert sym_name not in v_tmp_symbols
    v_tmp_symbols[sym_name] = []

    try:
        f = open(file_path)
    except:
        _pt_log(">>> open sym file error: %s" % sym_name)
    else:
        for line in f:

            assert line.count(" ") == 2
            splits = line.split(" ")
            assert len(splits) == 3
            # offset format: HEX
            func_item = (int(splits[0], 16), int(splits[1], 16), splits[2].strip("\n"))

            v_tmp_symbols[sym_name].append(func_item)
        f.close()


def load_sysdll_syms():
    """
        load self-parsed symbols of system dlls

        this should only be called once during each debug session

        !+ to export such xxx.txt symbol file, use my python scripts.
    """
    # xp sp3
    sym_path = os.path.join(file_dir, "symbols_xpsp3")
    for parent, dirnames, filenames in os.walk(sym_path):

        for dirname in dirnames:
            _pt_log(">>> load sysdll symbol, ignore dir: %s" % dirname)

        for filename in filenames:

            # only parse txt files
            if not filename.endswith(".txt"):
                # _pt_log(">>> load sysdll symbol, ignore file: %s" % filename)
                continue

            sym_name = filename.replace(".txt", "")
            # _pt_log("loading symbols for module %-10s from file: %s" % (sym_name, filename))
            _syms_load(sym_name.lower(), os.path.join(parent, filename))


def load_debugee_syms():
    """
        load self-parsed symbolf of debugee.
        this shall be called after debugee file set
    """
    target_file = util.gen_path_tail_debugee("_ida_names.txt", has_ext=False)
    if os.path.exists(target_file):

        _pt_log(">>> loading debugee symbol from file: %s" % target_file)
        _syms_load(util.debugee_name(), target_file)

    else:
        _pt_log(">>> debugee symbol file not found: %s" % target_file)


global v_tmp_pted_no_sym_md_names
v_tmp_pted_no_sym_md_names = []


def sym_resolve(md_name, offset):
    """
        resolve symbol from pre-loaded symbols

        @param: md_name : string : module name, as key in v_tmp_symbols
        @param: offset  : int    : offset that address relative to module base

        @return: tuple : (func_name, func_offset) or (None, None)
    """
    assert md_name and len(md_name) != 0

    md_name = md_name.lower()

    global v_tmp_symbols
    assert v_tmp_symbols and len(v_tmp_symbols) != 0

    # if debugee symbol not loaded, return None, but no "ASSERT", because it's quite common.
    if md_name == util.debugee_name() and md_name not in v_tmp_symbols:
        return (None, None)

    # if not, parse module, put txt file under folder, run this again
    if md_name not in v_tmp_symbols:

        global v_tmp_pted_no_sym_md_names
        if md_name not in v_tmp_pted_no_sym_md_names:
            _pt_log(">>> no sym for this md: %s" % md_name)
            v_tmp_pted_no_sym_md_names.append(md_name)

        # assert False
        # for sample loading dll of its own...
        return (None, None)

    for func_item in v_tmp_symbols[md_name]:
        if func_item[0] <= offset and offset <= func_item[1]:
            return (func_item[2], offset - func_item[0])

    return (None, None)


def get_sym_sys_dll_names():
    """
        get sys dll names that have symbols

        @return: list : a list of dict
    """
    global v_tmp_symbols
    if len(v_tmp_symbols) == 0:
        load_sysdll_syms()
    # all md names is lower()ed
    return v_tmp_symbols.keys()


def check_has_sys_dll_sym(sys_dll_name):
    """
        @param: sys_dll_name : string : system dll name

        @return: bool :
    """
    global v_tmp_symbols
    return sys_dll_name in v_tmp_symbols


def check_is_sys_dll(sys_dll_name):
    """
        @param: sys_dll_name : string : system dll name

        @return: bool :
    """
    global v_tmp_symbols
    return sys_dll_name in v_tmp_symbols


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
