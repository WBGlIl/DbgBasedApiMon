
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function
# from __future__ import unicode_literals


class breakpoint:
    '''
    Soft breakpoint object.
    '''

    address = None
    original_byte = None
    description = None
    restore = None
    handler = None

    # ---------------------------------------------------------------------------
    def __init__(self, address=None, original_byte=None, description="", restore=True, handler=None):
        '''
        @type  address:       DWORD
        @param address:       Address of breakpoint
        @type  original_byte: Byte
        @param original_byte: Original byte stored at breakpoint address
        @type  description:   String
        @param description:   (Optional) Description of breakpoint
        @type  restore:       Boolean
        @param restore:       (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @type  handler:       Function Pointer
        @param handler:       (Optional, def=None) Optional handler to call for this bp instead of the default handler
        '''

        self.address = address
        self.original_byte = original_byte
        self.description = description
        self.restore = restore
        self.handler = handler
