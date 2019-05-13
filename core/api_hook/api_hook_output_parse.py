# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# from __future__ import unicode_literals


# ---------------------------------------------------------------------------
# 变量


# ---------------------------------------------------------------------------
# 类 - 函数


def _parse_api_records():
    """
        parse global v_tmp_api_record_list, then return parsed results

        @return: tuple : (api_summaries_with_stacks, api_summaries_no_stacks)
                          api_summaries_with_stacks : list : a list of ApiHitWithStacks() object
                          api_summaries_no_stacks   : list : a list of ApiHitNoStacks() object
    """
    # convert to a new list of tuple, each item : (to_addr, api_name, from_func_name, stacks, param_str)
    #                                        or : (0, api_name, "", [], param_str)
    api_record_list = []
    for i in range(len(v_tmp_api_record_list)):

        tmp_record = v_tmp_api_record_list[i]

        api_name = tmp_record[0]
        from_func_name = tmp_record[0]
        stacks = tmp_record[1]
        to_addr = 0

        if len(stacks) != 0:

            # ---------------------------------------------------------------------------
            global v_tmp_is_pt_stacks_before_api_parse
            if v_tmp_is_pt_stacks_before_api_parse:
                _pt_log("before parsing stacks of api record...")
                _pt_log("api name: %s" % api_name)
                _pt_log("stack depth: %d" % len(stacks))
                for stack in stacks:
                    _pt_log("    %s" % stack)
                _pt_log("")
            # ---------------------------------------------------------------------------

            while len(stacks) > 1:

                to_addr = stacks[0].to_addr
                assert to_addr != 0

                # for most apis, from_func_name is valid.
                # but because we use self-parsed symbols, there are some "address" can't be "resolved", so we ignore this here.
                from_func_name = stacks[0].from_func_name
                # assert from_func_name and len(from_func_name) != 0

                if stacks[0].to_md_name is None or stacks[0].to_md_name == "":
                    # special call stacks like this:
                    # (0000B465)kernel32.dll._GetModuleFileNameW@12+00000000 | (016F0145)None.016F0145
                    # (016F0145)None.016F0145 | (0020AB1E)1111.exe.0060AB1E
                    # (0020AB1E)1111.exe.0060AB1E | (00002E78)1111.exe.00402E78
                    # (00002E78)1111.exe.00402E78 | (002129CF)1111.exe.006129CF
                    break

                # actually, we don't need to check from_md_name: stacks[0].from_md_name == util.debugee_name() or
                if stacks[0].to_md_name == util.debugee_name():
                    break

                stacks.pop(0)

            # if only 1 stack left, we ignore this whole record, but print details as remainder.
            if len(stacks) == 1:

                # print "*" * 100
                # print "parsing api record, ignore this one because it has only 1 stack: to_addr: %.8X, api_name: %s" % (to_addr, api_name)
                # print "    %s" % stacks[0]
                # print "*" * 100
                continue

        api_record_list.append((to_addr, api_name, from_func_name, stacks, tmp_record[2]))

    # make summary
    api_summaries_with_stacks = []
    api_summaries_no_stacks = []
    for api_record in api_record_list:

        api_name = api_record[1]
        stacks = api_record[3]
        param_str = api_record[4]

        if len(stacks) != 0:

            # with call stack, summary by to_addr
            # todo: special samples, different api may return to same to_addr, because sample invoke api in this way: call eax...
            # so for now, we just print it out...
            to_addr = api_record[0]
            assert to_addr != 0
            from_func_name = api_record[2]
            # this is possible
            # assert from_func_name is not None and len(from_func_name) != 0

            is_exist = False
            for summary in api_summaries_with_stacks:
                if to_addr == summary.to_addr:
                    is_exist = True
                    summary = api_summary_with_stacks__add_record(summary, api_name, from_func_name, stacks, param_str)
                    break

            if not is_exist:
                summary = _share_this.ApiHitWithStacks(to_addr, api_name, from_func_name)
                summary = api_summary_with_stacks__add_record(summary, api_name, from_func_name, stacks, param_str)
                api_summaries_with_stacks.append(summary)

        else:
            # no call stack, summary by api_name
            is_exist = False
            for summary in api_summaries_no_stacks:
                if summary.api_name == api_name:
                    is_exist = True
                    summary = api_summary_no_stacks__add_record(summary, param_str)
                    break

            if not is_exist:
                summary = _share_this.ApiHitNoStacks(api_name)
                summary = api_summary_no_stacks__add_record(summary, param_str)
                api_summaries_no_stacks.append(summary)

    return (api_summaries_with_stacks, api_summaries_no_stacks)


# ---------------------------------------------------------------------------
# main


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
