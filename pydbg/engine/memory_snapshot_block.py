
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function
# from __future__ import unicode_literals


class memory_snapshot_block:
    '''
    Memory block object, used in memory snapshots.
    '''

    mbi = None
    data = None

    # ---------------------------------------------------------------------------
    def __init__(self, mbi=None, data=None):
        '''
        @type  mbi:  MEMORY_BASIC_INFORMATION
        @param mbi:  MEMORY_BASIC_INFORMATION of memory block
        @type  data: Raw Bytes
        @param data: Raw bytes stored in memory block at time of snapshot
        '''

        self.mbi = mbi
        self.data = data
