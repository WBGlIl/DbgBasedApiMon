# -*- coding: utf-8 -*-


"""
anything else
"""

from __future__ import print_function
# from __future__ import unicode_literals


import os

import wmi
import inspect

from my_ctypes import *
from defines import *
from windows_h import *

file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))


# ---------------------------------------------------------------------------
# global main debugee name, set by xrkpydbg.py
global v_tmp_debugee_name
v_tmp_debugee_name = None

# global main debugee dir
global v_tmp_debugee_dir
v_tmp_debugee_dir = None


def debugee_name(has_ext=True):
    global v_tmp_debugee_name
    assert v_tmp_debugee_name is not None and len(v_tmp_debugee_name) != 0

    return has_ext and v_tmp_debugee_name or v_tmp_debugee_name.strip(".exe")


def debugee_dir():
    global v_tmp_debugee_dir
    return v_tmp_debugee_dir


def debugee_path():
    global v_tmp_debugee_name
    return os.path.abspath(v_tmp_debugee_name)


def gen_path_tail_debugee(tail, has_ext=True):
    """
        generate a path under debugee direcotry
    """
    global v_tmp_debugee_name
    assert v_tmp_debugee_name is not None and len(v_tmp_debugee_name) != 0
    global v_tmp_debugee_dir
    assert v_tmp_debugee_dir is not None and len(v_tmp_debugee_dir) != 0
    assert os.path.exists(v_tmp_debugee_dir)

    if has_ext:
        return os.path.join(v_tmp_debugee_dir, v_tmp_debugee_name + tail)
    else:
        return os.path.join(v_tmp_debugee_dir, v_tmp_debugee_name.strip(".exe") + tail)


def gen_path_prefix_time_tail_debugee(tail, has_ext=True):
    """
        generate a path under debugee directory, with time_str() as prefix
    """
    global v_tmp_debugee_name
    assert v_tmp_debugee_name is not None and len(v_tmp_debugee_name) != 0
    global v_tmp_debugee_dir
    assert v_tmp_debugee_dir is not None and len(v_tmp_debugee_dir) != 0
    assert os.path.exists(v_tmp_debugee_dir)

    if has_ext:
        return os.path.join(v_tmp_debugee_dir, time_str() + "_" + v_tmp_debugee_name + tail)
    else:
        return os.path.join(v_tmp_debugee_dir, time_str() + "_" + v_tmp_debugee_name.strip(".exe") + tail)


# ---------------------------------------------------------------------------


def file_handle_to_name(handle):
    """
        this handle does't belong to debuger, we need to duplicate the handle first
    """
    assert False
    # create a file mapping from the dll handle.
    file_map = kernel32.CreateFileMappingA(handle, 0, PAGE_READONLY, 0, 1, 0)

    if file_map:
        # map a single byte of the dll into memory so we can query for the file name.
        kernel32.MapViewOfFile.restype = POINTER(c_char)
        file_ptr = kernel32.MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 1)

        if file_ptr:
            # query for the filename of the mapped file.
            filename = create_string_buffer(2048)
            psapi.GetMappedFileNameA(kernel32.GetCurrentProcess(), file_ptr, byref(filename), 2048)

            # store the full path. this is kind of ghetto, but i didn't want to mess with QueryDosDevice() etc ...
            path = os.sep + filename.value.split(os.sep, 3)[3]
            kernel32.UnmapViewOfFile(file_ptr)

        kernel32.CloseHandle(file_map)
        return path


# ---------------------------------------------------------------------------


def save_buf_to_file(tail, data):
    """
        generate a file under debugee direcotry, with time_str() as prefix, and write binary data to file
    """
    file_path = gen_path_prefix_time_tail_debugee(tail, has_ext=False)
    assert not os.path.exists(file_path)
    try:
        file = open(file_path, "bw")
    except:
        pass
    else:
        file.write(data)
        file.close()


def pid_to_proc_path(pid):
    """
    """
    proc_path = "[Invalid]"

    c = wmi.WMI()
    for proc in c.Win32_Process():
        if pid == proc.ProcessId:
            proc_path = str(proc.Name)
            break

    return proc_path

# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
