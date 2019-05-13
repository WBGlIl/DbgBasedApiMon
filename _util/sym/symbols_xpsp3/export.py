# -*- coding: utf-8 -*-

"""
"""

import os
import inspect

import idc
import idaapi
import idautils

# no other module shall be loaded
# import xrk_log


# ---------------------------------------------------------------------------
py_file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))


# ---------------------------------------------------------------------------
v_log_header = "[XRK-EXPORT] >> "


def msg(str_):
    idaapi.msg("%s %s" % (v_log_header, str_))


# ---------------------------------------------------------------------------
def get_non_sub_functions(is_offset=False):
    """
        @param: is_offset : bool : is export offset or address

        @return: list : a list of tuple, each item: (start, end, name)
    """
    image_base = idaapi.get_imagebase()

    ret = []
    for f in idautils.Functions():
        name = idc.GetFunctionName(f)
        if not name.startswith("sub_") and not name.startswith("unknown"):

            start = idc.GetFunctionAttr(f, 0)
            end = idc.GetFunctionAttr(f, 4)
            if is_offset:
                start = start - image_base
                end = end - image_base

            ret.append((start, end, name))

    return ret


def save_non_sub_function(file_name, is_offset=False, is_hex=False):
    """
        @param: file_name : string : export file name
        @param: is_offset : bool   : is export offset or direct address
        @param: is_hex    : bool   : is export "value" as hex or int
    """
    f = open(file_name, "w")
    for func in get_non_sub_functions(is_offset=is_offset):

        if is_hex:
            f.write("%.8X %.8X %s\n" % (func[0], func[1], func[2]))
        else:
            f.write("%d %d %s\n" % (func[0], func[1], func[2]))
    f.close()
    # print "save non sub functio to file finish: %s" % file_name


# ---------------------------------------------------------------------------


exts_dict = {
    ".dll_": ".dll.txt",
    ".ime_": ".ime.txt",
    ".exe_": ".exe.txt",
    ".drv_": ".drv.txt",
    ".ocx_": ".ocx.txt"
}

if __name__ == "__main__":

    idb_path = idc.GetIdbPath()

    output_file = None
    for (ext, ext_x) in exts_dict.items():
        if os.path.exists(idb_path.replace(".idb", ext)):
            output_file = idb_path.replace(".idb", ext_x)
            break

    if output_file is None:
        msg("corresponding pe file not exists: %s" % idb_path)
        assert False
        exit(1)

    # we control whether replace or not from _gen_symbols.py, not from here
    # if os.path.exists(output_file):
    #     msg("can't export, file already exists: %s" % output_file)

    if os.path.exists(output_file):
        msg("replacing existing file: %s" % output_file)

    if output_file:
        save_non_sub_function(output_file, is_offset=True, is_hex=True)
        msg("xrkexport for xrkpydbg, finish: %s" % output_file)

    else:
        msg("xrkexport for xrkpydbg, no idb loaded")

    # we then exit
    idc.Exit(1)
