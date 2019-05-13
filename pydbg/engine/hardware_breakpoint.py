
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function
# from __future__ import unicode_literals


class hardware_breakpoint:
    '''
    Hardware breakpoint object.
    '''

    address = None
    length = None
    condition = None
    description = None
    restore = None
    slot = None
    handler = None

    # ---------------------------------------------------------------------------
    def __init__(self, address=None, length=0, condition="", description="", restore=True, slot=None, handler=None):
        '''

        @type  address:     DWORD
        @param address:     Address to set hardware breakpoint at
        @type  length:      Integer (1, 2 or 4)
        @param length:      Size of hardware breakpoint (byte, word or dword)
        @type  condition:   Integer (HW_ACCESS, HW_WRITE, HW_EXECUTE)
        @param condition:   Condition to set the hardware breakpoint to activate on
        @type  description: String
        @param description: (Optional) Description of breakpoint
        @type  restore:     Boolean
        @param restore:     (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @type  slot:        Integer (0-3)
        @param slot:        (Optional, Def=None) Debug register slot this hardware breakpoint sits in.
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler
        '''

        self.address = address
        self.length = length
        self.condition = condition
        self.description = description
        self.restore = restore
        self.slot = slot
        self.handler = handler
