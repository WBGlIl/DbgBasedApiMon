
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function
# from __future__ import unicode_literals


import random


class memory_breakpoint:
    '''
    Memory breakpoint object.
    '''

    address = None
    size = None
    mbi = None
    description = None
    handler = None

    read_count = 0                                # number of times the target buffer was read from
    split_count = 0                                # number of times this breakpoint was split
    copy_depth = 0                                # degrees of separation from original buffer
    id = 0                                # unique breakpoint identifier
    on_stack = False                            # is this memory breakpoint on a stack buffer?

    # ---------------------------------------------------------------------------
    def __init__(self, address=None, size=None, mbi=None, description="", handler=None):
        '''
        @type  address:     DWORD
        @param address:     Address of breakpoint
        @type  size:        Integer
        @param size:        Size of buffer we want to break on
        @type  mbi:         MEMORY_BASIC_INFORMATION
        @param mbi:         MEMORY_BASIC_INFORMATION of page containing buffer we want to break on
        @type  description: String
        @param description: (Optional) Description of breakpoint
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler
        '''

        self.address = address
        self.size = size
        self.mbi = mbi
        self.description = description
        self.handler = handler

        self.id = random.randint(0, 0xFFFFFFFF)    # unique breakpoint identifier
        self.read_count = 0                                # number of times the target buffer was read from
        self.split_count = 0                                # number of times this breakpoint was split
        self.copy_depth = 0                                # degrees of separation from original buffer
        self.on_stack = False                            # is this memory breakpoint on a stack buffer?
