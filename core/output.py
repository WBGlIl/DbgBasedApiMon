# -*- coding: utf-8 -*-

"""
all output stuff for ida
"""

# import os
import pickle

import log
import util
import _share_this


# ---------------------------------------------------------------------------
# global item to be set by xrkpydbg

# is pt stacks before parsing api
# global v_tmp_is_pt_stacks_before_api_parse
v_tmp_is_pt_stacks_before_api_parse = False

# is pt api summary collision when parsing api record
# global v_tmp_is_pt_parse_api_summary_collision
v_tmp_is_pt_parse_api_summary_collision = False


# ---------------------------------------------------------------------------

def _pt_log(line):
    """
        proxy to log.pt_log()
    """
    log.pt_log(line)


# ---------------------------------------------------------------------------
def export(file_path, pickle_obj, usage=""):
    """
    """
    try:
        file = open(file_path, "w")
    except:
        _pt_log("export %s to file cause exception: %s" % (usage, file_path))
    else:
        pickle.dump(pickle_obj, file)
        file.close()

        _pt_log("export %s to file: %s" % (usage, file_path))


# ---------------------------------------------------------------------------

# a list of tuple, each item: (api_name, stacks, param_str)
global v_tmp_api_record_list
v_tmp_api_record_list = []


def pt_api_summary():
    """
        print api summary
    """
    api_summaries_with_stacks, api_summaries_no_stacks = _parse_api_records()
    if len(api_summaries_with_stacks) == 0:
        _pt_log("!" * 5 + " no api call with stacks " + "!" * 5)

    else:
        _pt_log("!" * 5 + " api call with stacks count: %d " % len(api_summaries_with_stacks) + "!" * 5)
        for record in api_summaries_with_stacks:
            lines = record.lines()
            for line in lines:
                _pt_log("    %s" % line)
        _pt_log("")

    if len(api_summaries_no_stacks) == 0:
        _pt_log("!" * 5 + " no api call with none stacks " + "!" * 5)

    else:
        _pt_log("!" * 5 + " api call with none stacks count: %d " % len(api_summaries_no_stacks) + "!" * 5)
        for record in api_summaries_no_stacks:
            lines = record.lines()
            for line in lines:
                _pt_log("    %s" % line)
        _pt_log("")


def export_api_summary(file_path=None):
    """
        parse then export api summary to file

        @param: file_path : string : (optional, dft=None)output file path
    """
    if file_path is None:
        file_path = util.gen_path_prefix_time_tail_debugee("_api_summary.dat", has_ext=False)

    export(file_path, _parse_api_records(), "api summary")


# ---------------------------------------------------------------------------
# function call summary
class func_summary:
    def __init__(self):
        pass


global v_tmp_func_summary_list
v_tmp_func_summary_list = []


def add_func_summary():
    pass


def export_func_summary():
    pass


# ---------------------------------------------------------------------------
# function call stream
class func_stream:
    def __init__(self):
        pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
