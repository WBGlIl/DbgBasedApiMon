
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function
# from __future__ import unicode_literals


class memory_snapshot_context:
    '''
    Thread context object, used in memory snapshots.
    '''

    thread_id = None
    context = None

    # ---------------------------------------------------------------------------
    def __init__(self, thread_id=None, context=None):
        '''
        @type  thread_id:  Integer
        @param thread_id:  Thread ID
        @type  context:    CONTEXT
        @param context:    Context of thread specified by ID at time of snapshot
        '''

        self.thread_id = thread_id
        self.context = context
