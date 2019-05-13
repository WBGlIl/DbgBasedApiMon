# -*- coding: utf-8 -*-

"""

"""


from __future__ import print_function
# from __future__ import unicode_literals

import os.path

from my_ctypes import *
from defines import *
from windows_h import *

# macos compatability.
try:
    kernel32 = windll.kernel32
    psapi = windll.psapi
except:
    kernel32 = CDLL(os.path.join(os.path.dirname(__file__), "libmacdll.dylib"))
    psapi = kernel32

from pdx import *

import os


class SystemDll(object):
    '''
    System DLL descriptor object, used to keep track of loaded system DLLs and locations.

    @todo: Add PE parsing support.
    '''

    handle = None
    base = None
    name = None
    path = None
    pe = None
    size = 0

    # ---------------------------------------------------------------------------
    def __init__(self, handle, base):
        '''
        Given a handle and base address of the loaded DLL, determine the DLL name and size to fully initialize the
        system DLL object.

        @param: handle : HANDLE : Handle to the loaded DLL.
                                  the member is opened for reading and read-sharing in the context of the debugger
        @param: base   : int    : Loaded address of DLL

        @raise pdx: An exception is raised on failure.
        '''

        self.handle = handle
        self.base = base
        self.name = None
        self.path = None
        self.pe = None
        self.size = 0

        # calculate the file size of the
        file_size_hi = c_ulong(0)
        file_size_lo = 0
        file_size_lo = kernel32.GetFileSize(handle, byref(file_size_hi))
        self.size = (file_size_hi.value << 8) + file_size_lo

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
                self.path = os.sep + filename.value.split(os.sep, 3)[3]
                self.path = self.path.lower()

                # store the file name.
                # XXX - this really shouldn't be failing. but i've seen it happen.
                try:
                    self.name = filename.value[filename.value.rindex(os.sep) + 1:]
                except:
                    self.name = self.path
                self.name = self.name.lower()

                kernel32.UnmapViewOfFile(file_ptr)

            kernel32.CloseHandle(file_map)

    def __str__(self):
        return "%s(%.8X)" % (self.name, self.base)

    def is_same_sys_dll(self, sys_dll):
        return self.base == sys_dll.base and self.size == sys_dll.size and self.name == sys_dll.name

    # ---------------------------------------------------------------------------
    def __del__(self):
        '''
        Close the handle.
        '''

        kernel32.CloseHandle(self.handle)
