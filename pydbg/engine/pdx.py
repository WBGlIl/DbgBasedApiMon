# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# # from __future__ import unicode_literals


import os
import os.path

from my_ctypes import *
from defines import *

from _util.msdn import msdn

# macos compatability.
try:
    kernel32 = windll.kernel32
except:
    kernel32 = CDLL(os.path.join(os.path.dirname(__file__), "libmacdll.dylib"))


class pdx (Exception):
    '''
    This class is used internally for raising custom exceptions and includes support for automated Windows error message
    resolution and formatting. For example, to raise a generic error you can use::

        raise pdx("Badness occured.")

    To raise a Windows API error you can use::

        raise pdx("SomeWindowsApi()", True)
    '''

    dbg_msg = None
    error_code = None
    msdn_msg = None

    # ---------------------------------------------------------------------------
    def __init__(self, dbg_msg, win32_exception=False):
        '''
        '''
        self.dbg_msg = dbg_msg

        self.error_code = None
        self.msdn_msg = None

        if win32_exception:
            self.error_code = kernel32.GetLastError()
            self.msdn_msg = msdn.resolve_code_error(self.error_code)

            # import traceback
            # traceback.print_exc()
            print("[[错误]: code(0x%X) -> msg(%s)\n\n]" % (self.error_code, dbg_msg))
            print(self.msdn_msg)

            # self.error_msg = c_char_p()
            # kernel32.FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            #                         None,
            #                         self.error_code,
            #                         0x00000400,     # MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
            #                         byref(self.error_msg),
            #                         0,
            #                         None)

        else:
            # print ">>> exception : not win32 exception: %s" % (self.dbg_msg)
            pass

    # ---------------------------------------------------------------------------
    def __str__(self):
        """
        """
        if self.error_code is not None:
            return "code: %d, msg: %s - %s" % (self.error_code, self.dbg_msg, self.msdn_msg)
        else:
            return self.dbg_msg
