# -*- coding: utf-8 -*-

"""
generate symbols for each idb file under this same directory
"""


import os
import inspect
import subprocess

py_file_path = os.path.abspath(inspect.getsourcefile(lambda: 0))
py_file_dir = os.path.dirname(inspect.getsourcefile(lambda: 0))

# modify this by your own
idaw_path = r"D:\SoftWare\IDA Pro v6.8\idaw.exe"

# u need to modify export.py also.
target_exts = [".exe_", ".dll_", ".ime_", ".drv_", ".ocx_"]

if __name__ == "__main__":

    for parent, dirnames, filenames in os.walk(py_file_dir):

        # ignore sub-dirs
        for dirname in dirnames:
            print "ignore dir: %s" % dirname

        for filename in filenames:

            is_target = False
            for ext in target_exts:
                if filename.endswith(ext):
                    is_target = True
                    break
            if not is_target:
                continue

            # change these configs

            # is reparse all
            is_reparse_all = False
            if not is_reparse_all and os.path.exists(filename.strip("_") + ".txt"):
                print "ignore already parsed file: %s" % filename
                continue

            # print "parsing file: %s" % filename
            # continue

            py_export_path = os.path.join(py_file_dir, "export.py")
            dll_file_path = os.path.join(py_file_dir, filename)
            cmd_line = idaw_path + " " + "-A -S" + "\"" + py_export_path + "\" \"" + dll_file_path + "\""

            print "cmd_line: " + cmd_line

            # do not use os.system(cmd_line) here, which only parse first xxx.dll_
            # instead, subprocess will parse all xxx.dll_ one by one.
            subprocess.call(cmd_line)
            # break
