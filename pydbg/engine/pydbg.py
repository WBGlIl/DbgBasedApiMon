# -*- coding: utf-8 -*-

"""
pydbg 修改版
"""

from __future__ import print_function
# # from __future__ import unicode_literals  # 会导致读取进程内存的结果出现问题

import os
import os.path
import sys
import copy
import signal
import struct
import socket

import pydasm


sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))                   # pydbg
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))  # repo-pydbg
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))) + "\\core")        # core


from _util.util import *
from _util.sym import sym
from core_def import *

from my_ctypes import *
from defines import *
from windows_h import *

# macos compatability.
try:
    kernel32 = windll.kernel32
    advapi32 = windll.advapi32
    ntdll = windll.ntdll
    iphlpapi = windll.iphlpapi
except:
    kernel32 = CDLL(os.path.join(os.path.dirname(__file__), "libmacdll.dylib"))
    advapi32 = kernel32

from breakpoint import *
from hardware_breakpoint import *
from memory_breakpoint import *
from memory_snapshot_block import *
from memory_snapshot_context import *
from pdx import *
from system_dll import *
# from stack_walk import *


# ---------------------------------------------------------------------------
# global config

# is treat WaitForDebugEvent time out as process termination
v_tmp_is_treat_WaitForDebugEvent_as_termination = False


# ---------------------------------------------------------------------------
class PydbgEngine:
    """
    This class implements standard low leven functionality including:
        - The load() / attach() routines.
        - The main debug event loop.
        - Convenience wrappers for commonly used Windows API.
        - Single step toggling routine.
        - Win32 error handler wrapped around PDX.
        - Base exception / event handler routines which are meant to be overridden.

    Higher level functionality is also implemented including:
        - Register manipulation.
        - Soft (INT 3) breakpoints.
        - Memory breakpoints (page permissions).
        - Hardware breakpoints.
        - Exception / event handling call backs.
        - Pydasm (libdasm) disassembly wrapper.
        - Process memory snapshotting and restoring.
        - Endian manipulation routines.
        - Debugger hiding.
        - Function resolution.
        - "Intelligent" memory derefencing.
        - Stack/SEH unwinding.
        - Etc...
    """

    STRING_EXPLORATON_BUF_SIZE = 256
    STRING_EXPLORATION_MIN_LENGTH = 2

    # ---------------------------------------------------------------------------
    def __init__(self, ff=True, cs=False, is_log=False):
        """
        Set the default attributes. See the source if you want to modify the default creation values.

        @param: ff     : bool : (optional, dft=True)  is pydbg attaches to forked processes
        @param: cs     : bool : (optional, dft=False) is in client/server (socket) mode
        @param: is_log : bool : (optional, dft=False) is print log
        """
        # private variables, internal use only:
        self._restore_breakpoint = None      # breakpoint to restore
        self._guarded_pages = set()          # specific pages we set PAGE_GUARD on
        self._guards_active = True           # flag specifying whether or not guard pages are active

        self.call_stack_depth_max = 126

        self.page_size = 0                   # memory page size (dynamically resolved at run-time)
        self.pid = 0                         # debuggee's process id
        self.h_process = None                # debuggee's process handle
        self.h_thread = None                 # handle to current debuggee thread
        self.debugger_active = True          # flag controlling the main debugger event handling loop
        self.follow_forks = ff               # flag controlling whether or not pydbg attaches to forked processes
        self.client_server = cs              # flag controlling whether or not pydbg is in client/server mode
        self.callbacks = {}                  # exception callback handler dictionary
        self.system_dlls = []                # list of loaded system dlls
        self.dirty = False                   # flag specifying that the memory space of the debuggee was modified
        self.system_break = None             # the address at which initial and forced breakpoints occur at
        self.peb = None                      # process environment block address
        self.tebs = {}                       # dictionary of thread IDs to thread environment block addresses

        # internal variables specific to the last triggered exception.
        self.context = None                  # thread context of offending thread
        self.dbg_evt = None                      # DEBUG_EVENT
        self.exception_address = None        # from dbg.u.Exception.ExceptionRecord.ExceptionAddress
        self.write_violation = None          # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
        self.violation_address = None        # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]
        self.exception_code = None           # from dbg.u.Exception.ExceptionRecord.ExceptionCode

        # {0x123: breakpoint(), 0x234: breakpoint(), ...}
        self.breakpoints = {}                # internal breakpoint dictionary, keyed by address
        self.memory_breakpoints = {}         # internal memory breakpoint dictionary, keyed by base address
        self.hardware_breakpoints = {}       # internal hardware breakpoint array, indexed by slot (0-3 inclusive)
        self.memory_snapshot_blocks = []     # list of memory blocks at time of memory snapshot
        self.memory_snapshot_contexts = []   # list of threads contexts at time of memory snapshot

        self.first_breakpoint = True         # this flag gets disabled once the windows initial break is handled
        self.memory_breakpoint_hit = 0       # address of hit memory breakpoint or zero on miss

        self.mm_basic_info_list = []         # 内存基本信息结构(MEMORY_BASIC_INFORMATION)列表

        # designates whether or not the violation was in reaction to a memorybreakpoint hit or other unrelated event.
        self.hardware_breakpoint_hit = None      # hardware breakpoint on hit or None on miss

        # designates whether or not the single step event was in reaction to a hardware breakpoint hit or other unrelated event.
        self.instruction = None              # pydasm instruction object, propagated by self.disasm()
        self.mnemonic = None                 # pydasm decoded instruction mnemonic, propagated by self.disasm()
        self.op1 = None                      # pydasm decoded 1st operand, propagated by self.disasm()
        self.op2 = None                      # pydasm decoded 2nd operand, propagated by self.disasm()
        self.op3 = None                      # pydasm decoded 3rd operand, propagated by self.disasm()

        # control debug/error logging.
        if not is_log:
            self._log = lambda msg: None
        else:
            self._log = lambda msg: sys.stderr.write(">>> DBG_WARN  : %s\n" % msg)

        self._err = lambda msg: sys.stderr.write(">>> DBG_ERR   : %s\n" % msg)
        self._warn = lambda msg: sys.stderr.write(">>> DBG_WARN  : %s\n" % msg)
        self._high = lambda msg: sys.stderr.write("\n" + "*" * 100 + "\n>>> DBG_HIGH  : " + msg + "\n" + "*" * 100 + "\n")

        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

        # determine the system DbgBreakPoint address. this is the address at which initial and forced breaks happen.
        # XXX - need to look into fixing this for pydbg client/server.
        self.system_break = self.func_resolve("ntdll.dll", "DbgBreakPoint")

        self._log("system page size is %d" % self.page_size)

    # ---------------------------------------------------------------------------
    def load(self, path_to_file, command_line=None, create_new_console=False, show_window=True):
        """
        Load the specified executable and optional command line arguments into the debugger.

        @param: path_to_file       : string : Full path to executable to load in debugger
        @param: command_line       : string : (Optional, def=None) Command line arguments to pass to debuggee
        @param: create_new_console : bool   : (Optional, def=False) Create a new console for the debuggee.
        @param: show_window        : bool   : (Optional, def=True) Show / hide the debuggee window.

        @todo: This routines needs to be further tested ... I nomally just attach.
        @raise pdx: An exception is raised if we are unable to load the specified executable in the debugger.
        """
        pi = PROCESS_INFORMATION()
        si = STARTUPINFO()

        si.cb = sizeof(si)

        # these flags control the main window display of the debuggee.
        if not show_window:
            si.dwFlags = 0x1
            si.wShowWindow = 0x0

        # CreateProcess() seems to work better with command line arguments when the path_to_file is passed as NULL.
        if command_line:
            command_line = path_to_file + " " + command_line
            path_to_file = 0

        if self.follow_forks:
            creation_flags = DEBUG_PROCESS
        else:
            creation_flags = DEBUG_ONLY_THIS_PROCESS

        if create_new_console:
            creation_flags |= CREATE_NEW_CONSOLE

        success = kernel32.CreateProcessA(c_char_p(path_to_file),
                                          c_char_p(command_line),
                                          0,
                                          0,
                                          0,
                                          creation_flags,
                                          0,
                                          0,
                                          byref(si),
                                          byref(pi))

        if not success:
            raise pdx("CreateProcess Fail", True)

        # allow detaching on systems that support it.
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass

        # store the handles we need.
        self.pid = pi.dwProcessId
        self.h_process = pi.hProcess

        # resolve the PEB address.
        selector_entry = LDT_ENTRY()
        thread_context = self.get_thread_context(pi.hThread)

        if not kernel32.GetThreadSelectorEntry(pi.hThread, thread_context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        teb = selector_entry.BaseLow
        teb += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # add this TEB to the internal dictionary.
        self.tebs[pi.dwThreadId] = teb

        self.peb = self._read_process_memory(teb + 0x30, 4)
        self.peb = struct.unpack("<L", self.peb)[0]

        # if the function (CreateProcess) succeeds, be sure to call the CloseHandle function to close the hProcess and hThread handles when you are finished with them. -bill gates
        #
        # we keep the process handle open but don't need the thread handle.
        self.close_handle(pi.hThread)

    def attach(self, pid):
        """
        Attach to the specified process by PID.
        Saves a process handle in self.h_process and prevents debuggee from exiting on debugger quit.

        @param: pid : int : Process ID to attach to

        @raise pdx: An exception is raised on failure.
        @return: self :
        """

        self._log("attaching to pid %d" % pid)

        # obtain necessary debug privileges.
        self.get_debug_privileges()

        self.pid = pid
        self.open_process(pid)

        self.debug_active_process(pid)

        # allow detaching on systems that support it.
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass

        # enumerate the TEBs and add them to the internal dictionary.
        for thread_id in self.enumerate_threads():
            thread_handle = self.open_thread(thread_id)
            thread_context = self.get_thread_context(thread_handle)
            selector_entry = LDT_ENTRY()

            if not kernel32.GetThreadSelectorEntry(thread_handle, thread_context.SegFs, byref(selector_entry)):
                self.win32_error("GetThreadSelectorEntry()")

            self.close_handle(thread_handle)

            teb = selector_entry.BaseLow
            teb += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

            # add this TEB to the internal dictionary.
            self.tebs[thread_id] = teb

            # if the PEB has not been set yet, do so now.
            if not self.peb:
                self.peb = self._read_process_memory(teb + 0x30, 4)
                self.peb = struct.unpack("<L", self.peb)[0]

        return self.ret_self()

    def run(self):
        """
        Alias for debug_event_loop().
        """

        self.debug_event_loop()

    def detach(self):
        """
        Detach from debuggee.

        @return: self
        @raise pdx: An exception is raised on failure.
        """

        self._log("detaching from debuggee")

        # remove all software, memory and hardware breakpoints.
        self.bp_del_all()
        self.bp_del_mem_all()
        self.bp_del_hw_all()

        # try to detach from the target process if the API is available on the current platform.
        kernel32.DebugActiveProcessStop(self.pid)

        self.set_debugger_active(False)
        return self.ret_self()

    def terminate_process(self, exit_code=0, method="terminateprocess"):
        """
        Terminate the debuggee using the specified method.

        @param: exit_code : int    : (Optional, def=0) Exit code
        @param: method    : string : (Optonal, def="terminateprocess") Termination method. See __doc__ for more info.
                                     "terminateprocess": Terminate the debuggee by calling TerminateProcess(debuggee_handle).
                                     "exitprocess":      Terminate the debuggee by setting its current EIP to ExitProcess().

        @raise pdx: An exception is raised on failure.
        """

        if method.lower().startswith("exitprocess"):
            self.context.Eip = self.func_resolve_debuggee("kernel32", "ExitProcess")
            self.set_thread_context(self.context)

        # fall back to "terminateprocess".
        else:
            if not kernel32.TerminateProcess(self.h_process, exit_code):
                raise pdx("TerminateProcess(%d)" % exit_code, True)

    # ---------------------------------------------------------------------------
    # bp
    def bp_del(self, addr):
        """
        Removes the breakpoint from target addr.

        @param: addr : int : Address or list of addresses to remove breakpoint from

        @return: self :
        @raise pdx: An exception is raised on failure.
        """
        # if a list of addresses to remove breakpoints from was supplied.
        if type(addr) is list:
            # pass each lone addr to ourself.
            for addr in addr:
                self.bp_del(addr)

            return self.ret_self()

        self._log("bp_del(%08X )" % addr)

        # ensure a breakpoint exists at the target addr.
        if addr in self.breakpoints:
            # restore the original byte.
            self._write_process_memory(addr, self.breakpoints[addr].original_byte)
            self.set_attr("dirty", True)

            # remove the breakpoint from the internal list.
            del self.breakpoints[addr]

        return self.ret_self()

    def bp_del_all(self):
        """
        Removes all breakpoints from the debuggee.

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        self._log("bp_del_all()")

        for bp in self.breakpoints.keys():
            self.bp_del(bp)

        return self.ret_self()

    def bp_del_hw(self, addr=None, slot=None):
        """
        Removes the hardware breakpoint from the specified addr or slot.
        Either an addr or a slot must be specified, but not both.

        @param: addr : int : (Optional) Address to remove hardware breakpoint from.
        @param: slot    : int : (Optional)(0 through 3)

        @return: self :
        @raise pdx: An exception is raised on failure.
        """
        if addr == slot and slot is None:
            raise pdx("hw bp addr or slot # must be specified.")

        if not addr and slot not in xrange(4):
            raise pdx("invalid hw bp slot: %d. valid range is 0 through 3" % slot)

        # de-activate the hardware breakpoint for all active threads.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            if addr:
                if context.Dr0 == addr:
                    slot = 0
                elif context.Dr1 == addr:
                    slot = 1
                elif context.Dr2 == addr:
                    slot = 2
                elif context.Dr3 == addr:
                    slot = 3

            # mark slot as inactive.
            # bits 0, 2, 4, 6 for local  (L0 - L3)
            # bits 1, 3, 5, 7 for global (L0 - L3)

            context.Dr7 &= ~(1 << (slot * 2))

            # remove addr from the specified slot.
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000

            # remove the condition (RW0 - RW3) field from the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
            context.Dr7 &= ~(3 << ((slot * 4) + 16))

            # remove the length (LEN0-LEN3) field from the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
            context.Dr7 &= ~(3 << ((slot * 4) + 18))

            # set the thread context.
            self.set_thread_context(context, thread_id=thread_id)

        # remove the breakpoint from the internal list.
        del self.hardware_breakpoints[slot]

        return self.ret_self()

    def bp_del_hw_all(self):
        """
        Removes all hardware breakpoints from the debuggee.

        @raise pdx: An exception is raised on failure.
        @return: self :
        """
        if 0 in self.hardware_breakpoints:
            self.bp_del_hw(slot=0)
        if 1 in self.hardware_breakpoints:
            self.bp_del_hw(slot=1)
        if 2 in self.hardware_breakpoints:
            self.bp_del_hw(slot=2)
        if 3 in self.hardware_breakpoints:
            self.bp_del_hw(slot=3)

        return self.ret_self()

    def bp_del_mem(self, addr):
        """
        Removes the memory breakpoint from target addr.

        @param: addr : int : Address or list of addresses to remove memory breakpoint from

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        self._log("bp_del_mem(%08X )" % addr)

        # ensure a memory breakpoint exists at the target addr.
        if addr in self.memory_breakpoints:
            size = self.memory_breakpoints[addr].size
            mbi = self.memory_breakpoints[addr].mbi

            # remove the memory breakpoint from our internal list.
            del self.memory_breakpoints[addr]

            # page-aligned target memory range.
            start = mbi.BaseAddress
            end = addr + size                                  # non page-aligned range end
            end = end + self.page_size - (end % self.page_size)   # page-aligned range end

            # for each page in the target range, restore the original page permissions if no other breakpoint exists.
            for page in range(start, end, self.page_size):
                other_bp_found = False

                for mem_bp in self.memory_breakpoints.values():
                    if page <= mem_bp.addr < page + self.page_size:
                        other_bp_found = True
                        break
                    if page <= mem_bp.addr + size < page + self.page_size:
                        other_bp_found = True
                        break

                if not other_bp_found:
                    try:
                        self.virtual_protect(page, 1, mbi.Protect & ~PAGE_GUARD)

                        # remove the page from the set of tracked GUARD pages.
                        self._guarded_pages.remove(mbi.BaseAddress)
                    except:
                        pass

        return self.ret_self()

    def bp_del_mem_all(self):
        """
        Removes all memory breakpoints from the debuggee.

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        self._log("bp_del_mem_all()")

        for addr in self.memory_breakpoints.keys():
            self.bp_del_mem(addr)

        return self.ret_self()

    def bp_is_ours(self, address_to_check):
        """
        Determine if a breakpoint addr belongs to us.

        @param: address_to_check : int : Address to check if we have set a breakpoint at

        @return: bool : True if breakpoint in question is ours, False otherwise
        """
        if address_to_check in self.breakpoints:
            return True

        return False

    def bp_is_ours_mem(self, address_to_check):
        """
        Determines if the specified addr falls within the range of one of our memory breakpoints.
        When handling potential memory breakpoint exceptions it is mandatory to check the offending addr with this routine,
        as memory breakpoints are implemented by changing page permissions and the referenced addr may very well exist
        within the same page as a memory breakpoint but not within the actual range of the buffer we wish to break on.

        @param: address_to_check : int : Address to check if we have set a breakpoint on

        @rtype:  Mixed
        @return: The starting addr of the buffer our breakpoint triggered on or False if addr falls outside range.
        """

        for addr in self.memory_breakpoints:
            size = self.memory_breakpoints[addr].size

            if address_to_check >= addr and address_to_check <= addr + size:
                return addr

        return False

    def bp_set(self, address, description="", restore=True, handler=None):
        """
        Sets a breakpoint at the designated address.
        Register an EXCEPTION_BREAKPOINT callback handler to catch breakpoint events.
        If a list of addresses is submitted to this routine then the entire list of new breakpoints get the same description and restore.
        The optional "handler" parameter can be used to identify a function to specifically handle the specified bp, as opposed to the generic bp callback handler.
        The prototype of the callback routines is::

            func (pydbg)
                return DBG_CONTINUE     # or other continue status

        @param: address     : int or list : Address or list of addresses to set breakpoint at
        @param: description : string      : (Optional) Description to associate with this breakpoint
        @param: restore     : bool        : (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @param: handler     : method      : (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @return: self

        @raise pdx: An exception is raised on failure.
        """
        # if a list of addresses to set breakpoints on from was supplied
        if type(address) is list:
            # pass each lone address to ourself (each one gets the same description / restore flag).
            for addr in address:
                self.bp_set(addr, description, restore, handler)

            return self.ret_self()

        self._log("bp_set(%08X )" % address)

        # ensure a breakpoint doesn't already exist at the target address.
        if address not in self.breakpoints:
            try:
                # save the original byte at the requested breakpoint address.
                # self._log("bp_set -> read_process_memory - %X" % address)
                original_byte = self._read_process_memory(address, 1)

                # self._log("bp_set -> write_process_memory - %X" % address)
                # write an int3 into the target process space.
                self._write_process_memory(address, "\xCC")
                self.set_attr("dirty", True)

                # add the breakpoint to the internal list.
                self.breakpoints[address] = breakpoint(address, original_byte, description, restore, handler)
            except:
                raise pdx("Failed setting breakpoint at %08X " % address)

        return self.ret_self()

    def bp_set_hw(self, address, length, condition, description="", restore=True, handler=None):
        """
        Sets a hardware breakpoint at the designated address.
        Register an EXCEPTION_SINGLE_STEP callback handler to catch hardware breakpoint events.
        Setting hardware breakpoints requires the internal h_thread handle be set.
        This means that you can not set one outside the context of an debug event handler.
        If you want to set a hardware breakpoint as soon as you attach to or load a process, do so in the first chance breakpoint handler.

        For more information regarding the Intel x86 debug registers and hardware breakpoints see::

            http://pdos.csail.mit.edu/6.828/2005/readings/ia32/IA32-3.pdf
            Section 15.2

        Alternatively, you can register a custom handler to handle hits on the specific hw breakpoint slot.

        *Warning: Setting hardware breakpoints during the first system breakpoint will be removed upon process continue.
        A better approach is to set a software breakpoint that when hit will set your hardware breakpoints.

        @note: Hardware breakpoints are handled globally throughout the entire process and not a single specific thread.

        @param: address     : int    : Address to set hardware breakpoint at
        @param: length      : int    : Size of hardware breakpoint in bytes (byte, word or dword)(1, 2 or 4)
        @param: condition   : int    : Condition to set the hardware breakpoint to activate on(HW_ACCESS, HW_WRITE, HW_EXECUTE)
        @param: description : string : (Optional) Description of breakpoint
        @param: restore     : bool   : (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @param: handler     : method : (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @return: self :
        @raise pdx: An exception is raised on failure.
        """
        self._log("bp_set_hw(%08X , %d, %s)" % (address, length, condition))

        # instantiate a new hardware breakpoint object for the new bp to create.
        hw_bp = hardware_breakpoint(address, length, condition, description, restore, handler=handler)

        if length not in (1, 2, 4):
            raise pdx("invalid hw breakpoint length: %d." % length)

        # length -= 1 because the following codes are used for determining length:
        #       00 - 1 byte length
        #       01 - 2 byte length
        #       10 - undefined
        #       11 - 4 byte length
        length -= 1

        # condition table:
        #       00 - break on instruction execution only
        #       01 - break on data writes only
        #       10 - undefined
        #       11 - break on data reads or writes but not instruction fetches
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            raise pdx("invalid hw breakpoint condition: %d" % condition)

        # check for any available hardware breakpoint slots. there doesn't appear to be any difference between local
        # and global as far as we are concerned on windows.
        #
        #     bits 0, 2, 4, 6 for local  (L0 - L3)
        #     bits 1, 3, 5, 7 for global (G0 - G3)
        #
        # we could programatically search for an open slot in a given thread context with the following code:
        #
        #    available = None
        #    for slot in xrange(4):
        #        if context.Dr7 & (1 << (slot * 2)) == 0:
        #            available = slot
        #            break
        #
        # but since we are doing global hardware breakpoints, we rely on ourself for tracking open slots.

        if 0 not in self.hardware_breakpoints:
            available = 0
        elif 1 not in self.hardware_breakpoints:
            available = 1
        elif 2 not in self.hardware_breakpoints:
            available = 2
        elif 3 not in self.hardware_breakpoints:
            available = 3
        else:
            raise pdx("no hw breakpoint slots available.")

        # activate the hardware breakpoint for all active threads.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # mark available debug register as active (L0 - L3).
            context.Dr7 |= 1 << (available * 2)

            # save our breakpoint address to the available hw bp slot.
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address

            # set the condition (RW0 - RW3) field for the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
            context.Dr7 |= condition << ((available * 4) + 16)

            # set the length (LEN0-LEN3) field for the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
            context.Dr7 |= length << ((available * 4) + 18)

            # set the thread context.
            self.set_thread_context(context, thread_id=thread_id)

        # update the internal hardware breakpoint array at the used slot index.
        hw_bp.slot = available
        self.hardware_breakpoints[available] = hw_bp

        return self.ret_self()

    def bp_set_mem(self, address, size, description="", handler=None):
        """
        Sets a memory breakpoint at the target address.
        This is implemented by changing the permissions of the page containing the address to PAGE_GUARD.
        To catch memory breakpoints you have to register the EXCEPTION_GUARD_PAGE callback.
        Within the callback handler check the internal pydbg variable self.memory_breakpoint_hit to determine if the violation was a result of a direct memory breakpoint hit or some unrelated event.
        Alternatively, you can register a custom handler to handle the memory breakpoint.
        Memory breakpoints are automatically restored via the internal single step handler.
        To remove a memory breakpoint, you must explicitly call bp_del_mem().

        @param: address     : int    : Starting address of the buffer to break on
        @param: size        : int    : Size of the buffer to break on
        @param: description : string : (Optional) Description to associate with this breakpoint
        @param: handler     : method : (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        self._log("bp_set_mem() buffer range is %08X  - %08X " % (address, address + size))

        # ensure the target address doesn't already sit in a memory breakpoint range:
        if self.bp_is_ours_mem(address):
            self._log("a memory breakpoint spanning %08X  already exists" % address)
            return self.ret_self()

        # determine the base address of the page containing the starting point of our buffer.
        try:
            mbi = self.virtual_query(address)
        except:
            raise pdx("bp_set_mem(): failed querying address: %08X " % address)

        self._log("buffer starting at %08X  sits on page starting at %08X " % (address, mbi.BaseAddress))

        # individually change the page permissions for each page our buffer spans.
        # why do we individually set the page permissions of each page as opposed to a range of pages? because empirical
        # testing shows that when you set a PAGE_GUARD on a range of pages, if any of those pages are accessed, then
        # the PAGE_GUARD attribute is dropped for the entire range of pages that was originally modified. this is
        # undesirable for our purposes when it comes to the ease of restoring hit memory breakpoints.
        current_page = mbi.BaseAddress

        while current_page <= address + size:
            self._log("changing page permissions on %08X " % current_page)

            # keep track of explicitly guarded pages, to differentiate from pages guarded by the debuggee / OS.
            self._guarded_pages.add(current_page)
            self.virtual_protect(current_page, 1, mbi.Protect | PAGE_GUARD)

            current_page += self.page_size

        # add the breakpoint to the internal list.
        self.memory_breakpoints[address] = memory_breakpoint(address, size, mbi, description, handler)

        return self.ret_self()

    # ---------------------------------------------------------------------------
    # misc - check

    def duplicate_handle(self, src_handle):
        """
            handle shall be closed by user

            @return: HANDLE :
                   : False  : failure
        """
        ret = c_uint32()
        if kernel32.DuplicateHandle(self.h_process, src_handle, kernel32.GetCurrentProcess(), byref(ret), 0, False, 2):
            return ret.value
        else:
            self._err("duplicate handle failure: %d" % kernel32.GetLastError())
            return False

    def is_address_on_stack(self, address, context=None):
        """
        Utility function to determine if the specified address exists on the current thread stack or not.

        @param: address : int     : Address to check
        @param: context : Context : (Optional) Current thread context to examine

        @return: bool : True if address lies in current threads stack range, False otherwise.
        """
        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        assert context is not None
        (stack_top, stack_bottom) = self.stack_range(context)

        if address >= stack_bottom and address <= stack_top:
            return True

        return False

    def is_address_in_modules(self, address):
        """
            check if address in modules

            @param: address : int : address to check

            @return: bool :
        """
        for module in self.iterate_modules():
            if module.modBaseAddr < address < module.modBaseAddr + module.modBaseSize:
                return True
        return False

    def is_address_valid(self, address):
        """
            check if address valid
        """
        # return self.is_address_in_modules(address) or self.is_address_on_stack(address)
        if address is None or address == 0:
            return False

        if self.is_address_in_modules(address):
            return True

        # 正常情况下, 上面那个判断就可以了. 但这里不知道为啥不正常, 所以还要再加一层
        for sys_dll in self.system_dlls:
            if sys_dll.base <= address and address <= sys_dll.base + sys_dll.size:
                return True

        return self.context is not None and self.is_address_on_stack(address)

    def is_mm_valid(self, address, size):
        """
            check if mm range valid

            TODO:
        """
        return self.is_address_valid(address) and self.is_address_valid(address + size)

    # ---------------------------------------------------------------------------
    # addr to xxx
    def addr_to_system_dll(self, address):
        """
        Return the system DLL that contains the address specified.

        @param: address : int : Address to search system DLL ranges for

        @return: system_dll obj or None : System DLL that contains the address specified or None if not found.
        """
        for dll in self.system_dlls:
            if dll.base <= address and address <= dll.base + dll.size:
                return dll

        return None

    def addr_to_module(self, address):
        """
        Return the MODULEENTRY32 structure for the module that contains the address specified.

        @param: address : int : Address to search loaded module ranges for

        @rtype:  MODULEENTRY32
        @return: MODULEENTRY32 strucutre that contains the address specified or None if not found.
        """
        found = None

        for module in self.iterate_modules():
            if module.modBaseAddr <= address and address <= module.modBaseAddr + module.modBaseSize:
                # we have to make a copy of the 'module' since it is an iterator and will be blown away.
                # the reason we can't "break" out of the loop is because there will be a handle leak.
                # and we can't use enumerate_modules() because we need the entire module structure.
                # so there...
                found = copy.copy(module)

        return found

    def addr_resolve(self, addr):
        """
            resolve address to some string

            @return: string :
        """
        md = self.addr_to_module(addr)
        if md:
            # offset = addr - md.modBaseAddr
            # (func_name, func_offset) = sym.sym_resolve(md.szModule, offset)
            # if func_name is None or func_offset is None:
            #     return "%s.%.8X" % (md.szModule, offset)
            # else:
            #     return "(%.8X)%s.%s+%.8X" % (offset, md.szModule, func_name, func_offset)
            return "%s+%.8X" % (md.szModule, addr - md.modBaseAddr)
        else:
            # addr_to_module() 貌似枚举不到 ntdll.dll, 所以这里再来一次这个
            sys_dll = self.addr_to_system_dll(addr)
            if sys_dll:
                return "%s+%.8X" % (sys_dll.name, addr - sys_dll.base)
            else:
                mdi = self.get_mbi_by_addr(addr)
                if not mdi:
                    return "0x%.8X(no-page)" % addr
                else:
                    return "0x%.8X+0x%.8X" % (mdi.BaseAddress, addr - mdi.BaseAddress)

    # ---------------------------------------------------------------------------
    # misc
    def get_attr(self, attribute):
        """
        Return the value for the specified class attribute.
        This routine should be used over directly accessing class member variables for transparent support across local vs. client/server debugger clients.

        @type  attribute: String
        @param: attribute: Name of attribute to return.

        @rtype:  Mixed
        @return: Requested attribute or None if not found.
        """

        if not hasattr(self, attribute):
            return None

        return getattr(self, attribute)

    def disasm(self, addr):
        """
        Pydasm disassemble utility function wrapper. Stores the pydasm decoded instruction in self.instruction.

        @param: addr : int : Address to disassemble at

        @return: string : Disassembled string.
        """

        try:
            data = self._read_process_memory(addr, 32)
        except:
            return "Unable to disassemble at %08X " % addr

        # update our internal member variables.
        self.instruction = pydasm.get_instruction(data, pydasm.MODE_32)

        if not self.instruction:
            self.mnemonic = "[UNKNOWN]"
            self.op1 = ""
            self.op2 = ""
            self.op3 = ""

            return "[UNKNOWN]"
        else:
            self.mnemonic = pydasm.get_mnemonic_string(self.instruction, pydasm.FORMAT_INTEL)
            self.op1 = pydasm.get_operand_string(self.instruction, 0, pydasm.FORMAT_INTEL, address)
            self.op2 = pydasm.get_operand_string(self.instruction, 1, pydasm.FORMAT_INTEL, address)
            self.op3 = pydasm.get_operand_string(self.instruction, 2, pydasm.FORMAT_INTEL, address)

            # the rstrip() is for removing extraneous trailing whitespace that libdasm sometimes leaves.
            return pydasm.get_instruction_string(self.instruction, pydasm.FORMAT_INTEL, address).rstrip(" ")

    def disasm_around(self, addr, num_inst=5):
        """
        Given a specified address this routine will return the list of 5 instructions before and after the instruction at address (including the instruction at address, so 11 instructions in total).
        This is accomplished by grabbing a larger chunk of data around the address than what is predicted as necessary and then disassembling forward.
        If during the forward disassembly the requested address lines up with the start of an instruction, then the assumption is made that the forward disassembly self corrected itself and the instruction set is returned.
        If we are unable to align with the original address, then we modify our data slice and try again until we do.

        @param: address  : int : Address to disassemble around
        @param: num_inst : int : (Optional, Def=5) Number of instructions to disassemble up/down from address

        @return: List of tuples (address, disassembly) of instructions around the specified address.
        """

        if num_inst == 0:
            return [(addr, self.disasm(addr))]

        if num_inst < 0 or not int == type(num_inst):
            self._err("disasm_around called with an invalid window size. reurning error value")
            return [(addr, "invalid window size supplied")]

        # grab a safe window size of bytes.
        window_size = (num_inst * 64) / 5

        # grab a window of bytes before and after the requested address.
        try:
            data = self._read_process_memory(addr - window_size, window_size * 2)
        except:
            return [(addr, "Unable to disassemble")]

        # the rstrip() is for removing extraneous trailing whitespace that libdasm sometimes leaves.
        i = pydasm.get_instruction(data[window_size:], pydasm.MODE_32)
        disassembly = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, addr).rstrip(" ")
        complete = False
        start_byte = 0

        # loop until we retrieve a set of instructions that align to the requested addr.
        while not complete:
            instructions = []
            slice = data[start_byte:]
            offset = 0

            # step through the bytes in the data slice.
            while offset < len(slice):
                i = pydasm.get_instruction(slice[offset:], pydasm.MODE_32)

                if not i:
                    break

                # calculate the actual address of the instruction at the current offset and grab the disassembly
                addr = addr - window_size + start_byte + offset
                inst = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, addr).rstrip(" ")

                # add the address / instruction pair to our list of tuples.
                instructions.append((addr, inst))

                # increment the offset into the data slice by the length of the current instruction.
                offset += i.length

            # we're done processing a data slice.
            # step through each addres / instruction tuple in our instruction list looking for an instruction alignment
            # match. we do the match on address and the original disassembled instruction.
            index_of_address = 0
            for (addr, inst) in instructions:
                if addr == addr and inst == disassembly:
                    complete = True
                    break

                index_of_address += 1

            start_byte += 1

        return instructions[index_of_address - num_inst:index_of_address + num_inst + 1]

    def func_resolve(self, dll, function):
        """
        Utility function that resolves the address of a given module / function name pair under the context of the debugger.

        @param: dll      : string : Name of the DLL (case-insensitive)
        @param: function : string : Name of the function to resolve (case-sensitive)

        @return: int : Address
        """
        handle = kernel32.LoadLibraryA(dll)
        addr = kernel32.GetProcAddress(handle, function)

        kernel32.FreeLibrary(handle)

        return addr

    def func_resolve_debuggee(self, dll_name, func_name):
        """
        Utility function that resolves the address of a given module / function name pair under the context of the debuggee.
        Note: Be weary of calling this function from within a LOAD_DLL handler as the module is not yet fully loaded and therefore the snapshot will not include it.

        @param: dll_name  : string : Name of the DLL (case-insensitive, ex:ws2_32.dll)
        @param: func_name : string : Name of the function to resolve (case-sensitive)

        @return: int : Address of the symbol in the target process address space if it can be resolved, None otherwise
        """

        dll_name = dll_name.lower()

        # we can't make the assumption that all DLL names end in .dll, for example Quicktime libs end in .qtx / .qts
        # so instead of this old line:
        #     if not dll_name.endswith(".dll"):
        # we'll check for the presence of a dot and will add .dll as a conveneince.
        if not dll_name.count("."):
            dll_name += ".dll"

        for module in self.iterate_modules():
            if module.szModule.lower() == dll_name:
                base_address = module.modBaseAddr
                dos_header = self._read_process_memory(base_address, 0x40)

                # check validity of DOS header.
                if len(dos_header) != 0x40 or dos_header[:2] != "MZ":
                    continue

                e_lfanew = struct.unpack("<I", dos_header[0x3c:0x40])[0]
                pe_headers = self._read_process_memory(base_address + e_lfanew, 0xF8)

                # check validity of PE headers.
                if len(pe_headers) != 0xF8 or pe_headers[:2] != "PE":
                    continue

                export_directory_rva = struct.unpack("<I", pe_headers[0x78:0x7C])[0]
                export_directory_len = struct.unpack("<I", pe_headers[0x7C:0x80])[0]
                export_directory = self._read_process_memory(base_address + export_directory_rva, export_directory_len)
                # num_of_functions = struct.unpack("<I", export_directory[0x14:0x18])[0]
                num_of_names = struct.unpack("<I", export_directory[0x18:0x1C])[0]
                address_of_functions = struct.unpack("<I", export_directory[0x1C:0x20])[0]
                address_of_names = struct.unpack("<I", export_directory[0x20:0x24])[0]
                address_of_ordinals = struct.unpack("<I", export_directory[0x24:0x28])[0]
                name_table = self._read_process_memory(base_address + address_of_names, num_of_names * 4)

                # perform a binary search across the function names.
                low = 0
                high = num_of_names

                while low <= high:
                    # python does not suffer from integer overflows:
                    #     http://googleresearch.blogspot.com/2006/06/extra-extra-read-all-about-it-nearly.html
                    middle = (low + high) / 2
                    current_address = base_address + struct.unpack("<I", name_table[middle * 4:(middle + 1) * 4])[0]

                    # we use a crude approach here. read 256 bytes and cut on NULL char. not very beautiful, but reading
                    # 1 byte at a time is very slow.
                    name_buffer = self._read_process_memory(current_address, 256)
                    name_buffer = name_buffer[:name_buffer.find("\0")]

                    if name_buffer < func_name:
                        low = middle + 1
                    elif name_buffer > func_name:
                        high = middle - 1
                    else:
                        # MSFT documentation is misleading - see http://www.bitsum.com/pedocerrors.htm
                        bin_ordinal = self._read_process_memory(base_address + address_of_ordinals + middle * 2, 2)
                        ordinal = struct.unpack("<H", bin_ordinal)[0]   # ordinalBase has already been subtracted
                        bin_func_address = self._read_process_memory(base_address + address_of_functions + ordinal * 4, 4)
                        function_address = struct.unpack("<I", bin_func_address)[0]

                        return base_address + function_address

                # function was not found.
                return None

        # module was not found.
        return None

    def hide_debugger(self):
        """
        Hide the presence of the debugger.
        This routine hides the debugger in the following ways:

            - Modifies the PEB flag that IsDebuggerPresent() checks for.

        @raise pdx: An exception is raised if we are unable to hide the debugger for various reasons.

        !+ This routine requires an active context and therefore can not be called immediately after a load() for example.
           Call it from the first chance breakpoint handler.
        """

        selector_entry = LDT_ENTRY()

        # a current thread context is required.
        if not self.context:
            raise pdx("hide_debugger(): a thread context is required. Call me from a breakpoint handler.")

        if not kernel32.GetThreadSelectorEntry(self.h_thread, self.context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        fs_base = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # http://openrce.org/reference_library/files/reference/Windows Memory Layout, User-Kernel Address Spaces.pdf
        # find the peb.
        peb = self._read_process_memory(fs_base + 0x30, 4)
        peb = self.flip_endian_dword(peb)

        # zero out the flag. (3rd byte)
        self._write_process_memory(peb + 2, "\x00", 1)

        return self.ret_self()

    def hide_debugger_x(self):
        """
            many types to hide debugger
        """
        pass

    def hide_run_in_vm(self):
        pass

    def flip_endian(self, dword):
        """
        Utility function to flip the endianess a given DWORD into raw bytes.

        @param: dowrd : int : DWORD whose endianess to flip

        @return: raw : Converted DWORD in raw bytes.
        """

        byte1 = chr(dword % 256)
        dword = dword >> 8
        byte2 = chr(dword % 256)
        dword = dword >> 8
        byte3 = chr(dword % 256)
        dword = dword >> 8
        byte4 = chr(dword % 256)

        return "%c%c%c%c" % (byte1, byte2, byte3, byte4)

    def flip_endian_dword(self, bytes):
        """
        Utility function to flip the endianess of a given set of raw bytes into a DWORD.

        @param: bytes : raw : Raw bytes whose endianess to flip

        @return: int : Converted DWORD.
        """

        return struct.unpack("<L", bytes)[0]

    # ---------------------------------------------------------------------------
    # iter - enum
    def iterate_modules(self):
        """
        A simple iterator function that can be used to iterate through all modules the target process has mapped in its address space.
        Yielded objects are of type MODULEENTRY32.

        @return: MODULEENTRY32 : Iterated module entries.
        @warning: break-ing out of loops over this routine will cause a handle leak.
        """

        # self._log("iterate_modules()")

        current_entry = MODULEENTRY32()
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        current_entry.dwSize = sizeof(current_entry)

        if not kernel32.Module32First(snapshot, byref(current_entry)):
            return

        while 1:
            yield current_entry

            if not kernel32.Module32Next(snapshot, byref(current_entry)):
                break

        # if the above loop is "broken" out of, then this handle leaks.
        self.close_handle(snapshot)

    def get_md_names(self):
        """
            get loaded module names

            @return: list : a list of string
        """
        ret = []
        for md in self.iterate_modules():
            ret.append(md.szModule)
        return ret

    def get_md(self, md_name):
        """
            get module by module name

            @param: md_name : string :

            @return: MODULEENTRY32 or None
        """
        for md in self.iterate_modules():
            if md.szModule == md_name:
                return md
        return None

    def check_has_module(self, md_name):
        """
            check if module loaded

            @param: md_name : string : module full name
        """
        for md in self.iterate_modules():
            if md.szModule == md_name:
                return True
        return False

    def iterate_processes(self):
        """
        A simple iterator function that can be used to iterate through all running processes.
        Yielded objects are of type PROCESSENTRY32.

        @return: PROCESSENTRY32 : Iterated process entries.
        @warning: break-ing out of loops over this routine will cause a handle leak.
        """

        self._log("iterate_processes()")

        pe = PROCESSENTRY32()
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        if not kernel32.Process32First(snapshot, byref(pe)):
            return

        while 1:
            yield pe

            if not kernel32.Process32Next(snapshot, byref(pe)):
                break

        # if the above loop is "broken" out of, then this handle leaks.
        self.close_handle(snapshot)

    def iterate_threads(self):
        """
        A simple iterator function that can be used to iterate through all running processes.
        Yielded objects are of type THREADENTRY32.

        @return: THREADENTRY32 : Iterated process entries.
        @warning: break-ing out of loops over this routine will cause a handle leak.
        """

        self._log("iterate_threads()")

        thread_entry = THREADENTRY32()
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Thread32First() will fail.
        thread_entry.dwSize = sizeof(thread_entry)

        if not kernel32.Thread32First(snapshot, byref(thread_entry)):
            return

        while 1:
            if thread_entry.th32OwnerProcessID == self.pid:
                yield thread_entry

            if not kernel32.Thread32Next(snapshot, byref(thread_entry)):
                break

        # if the above loop is "broken" out of, then this handle leaks.
        self.close_handle(snapshot)

    def get_proc_mbi_list(self):
        """获取所有的页面"""
        mbi_list = []
        tmp = 0
        while tmp < 0x7FFFFFFF:
            try:
                mbi = self.virtual_query(tmp)
                if mbi:
                    mbi_list.append(mbi)
                    tmp += mbi.RegionSize
                else:
                    tmp += self.page_size
            except:
                tmp += self.page_size

        return mbi_list

    def update_proc_mbi_list(self):
        self.mm_basic_info_list = self.get_proc_mbi_list()

    def _get_mbi_by_addr_raw(self, addr):
        for mbi in self.mm_basic_info_list:
            if mbi.BaseAddress <= addr and addr <= mbi.BaseAddress + mbi.RegionSize:
                return mbi
        return None

    def get_mbi_by_addr(self, addr):
        """由地址获取所在内存的基本信息"""
        if len(self.mm_basic_info_list) == 0:
            self.update_proc_mbi_list()
            return self._get_mbi_by_addr_raw(addr)

        else:
            mbi = self._get_mbi_by_addr_raw(addr)
            if not mbi:
                self.update_proc_mbi_list()
                mbi = self._get_mbi_by_addr_raw(addr)
            return mbi

    def get_page_base_by_addr(self, addr):
        mbi = self.get_mbi_by_addr(addr)
        if mbi:
            return mbi.BaseAddress
        else:
            return None

    def enumerate_modules(self):
        """
        Using the CreateToolhelp32Snapshot() API enumerate and return the list of module name / base address tuples that belong to the debuggee

        @return: list : List of module name / base address tuples.
        """

        self._log("enumerate_modules()")

        module = MODULEENTRY32()
        module_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        module.dwSize = sizeof(module)

        found_mod = kernel32.Module32First(snapshot, byref(module))

        while found_mod:
            module_list.append((module.szModule, module.modBaseAddr))
            found_mod = kernel32.Module32Next(snapshot, byref(module))

        self.close_handle(snapshot)
        return module_list

    def enumerate_processes(self):
        """
        Using the CreateToolhelp32Snapshot() API enumerate all system processes returning a list of pid / process name tuples.

        @return: list : List of pid / process name tuples.

        Example::

            for (pid, name) in pydbg.enumerate_processes():
                if name == "test.exe":
                    break

            pydbg.attach(pid)
        """

        self._log("enumerate_processes()")

        pe = PROCESSENTRY32()
        process_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        found_proc = kernel32.Process32First(snapshot, byref(pe))

        while found_proc:
            process_list.append((pe.th32ProcessID, pe.szExeFile))
            found_proc = kernel32.Process32Next(snapshot, byref(pe))

        self.close_handle(snapshot)
        return process_list

    def enumerate_threads(self):
        """
        Using the CreateToolhelp32Snapshot() API enumerate all system threads returning a list of thread IDs that belong to the debuggee.

        @return: list : List of tid belonging to the debuggee.

        Example::
            for thread_id in self.enumerate_threads():
                context = self.get_thread_context(None, thread_id)
        """

        self._log("enumerate_threads()")

        thread_entry = THREADENTRY32()
        debuggee_threads = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Thread32First() will fail.
        thread_entry.dwSize = sizeof(thread_entry)

        success = kernel32.Thread32First(snapshot, byref(thread_entry))

        while success:
            if thread_entry.th32OwnerProcessID == self.pid:
                debuggee_threads.append(thread_entry.th32ThreadID)

            success = kernel32.Thread32Next(snapshot, byref(thread_entry))

        self.close_handle(snapshot)
        return debuggee_threads

    def enumerate_mm_pages(self):
        """
        """
        pass

    # ---------------------------------------------------------------------------
    # win32
    def close_handle(self, handle):
        """
        Convenience wraper around kernel32.CloseHandle()

        @param: handle : HANDLE : Handle to close

        @return: bool : Return value from CloseHandle().
        """
        return kernel32.CloseHandle(handle)

    def win32_error(self, prefix=None):
        """
        Convenience wrapper around GetLastError() and FormatMessage().
        Raises an exception with the relevant error code and formatted message.

        @param: prefix : string : (Optional) String to prefix error message with.

        @raise pdx: An exception is always raised by this routine.
        """

        error = c_char_p()
        error_code = kernel32.GetLastError()

        kernel32.FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                None,
                                error_code,
                                0x00000400,     # MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
                                byref(error),
                                0,
                                None)
        if prefix:
            error_message = "%s: %s" % (prefix, error.value)
        else:
            error_message = "GetLastError(): %s" % error.value

        raise pdx(error_message, error_code)

    def debug_active_process(self, pid):
        """
        Convenience wrapper around GetLastError() and FormatMessage().
        Returns the error code and formatted message associated with the last error.
        You probably do not want to call this directly, rather look at attach().

        @param: pid : int : Process ID to attach to

        @raise pdx: An exception is raised on failure.
        """

        if not kernel32.DebugActiveProcess(pid):
            raise pdx("DebugActiveProcess(%d)" % pid, True)

    def debug_event_iteration(self):
        """
        Check for and process a debug event.
        """

        continue_status = DBG_CONTINUE
        dbg_evt = DEBUG_EVENT()

        # wait for a debug event.
        if kernel32.WaitForDebugEvent(byref(dbg_evt), 100) != 0:
            # grab various information with regards to the current exception.
            self.h_thread = self.open_thread(dbg_evt.dwThreadId)
            self.context = self.get_thread_context(self.h_thread)
            self.dbg_evt = dbg_evt
            self.exception_address = dbg_evt.u.Exception.ExceptionRecord.ExceptionAddress
            self.write_violation = dbg_evt.u.Exception.ExceptionRecord.ExceptionInformation[0]
            self.violation_address = dbg_evt.u.Exception.ExceptionRecord.ExceptionInformation[1]
            self.exception_code = dbg_evt.u.Exception.ExceptionRecord.ExceptionCode

            if dbg_evt.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                self._log(">>> evt(%.8X): create process" % (self.dbg_evt.dwThreadId))
                continue_status = self.event_handler_create_process()

            elif dbg_evt.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                self._log(">>> evt(%.8X): create thread" % (self.dbg_evt.dwThreadId))
                continue_status = self.event_handler_create_thread()

            elif dbg_evt.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                self._log(">>> evt(%.8X): exit process" % (self.dbg_evt.dwThreadId))
                continue_status = self.event_handler_exit_process()

            elif dbg_evt.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                self._log(">>> evt(%.8X): exit thread" % (self.dbg_evt.dwThreadId))
                continue_status = self.event_handler_exit_thread()

            elif dbg_evt.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                continue_status = self.event_handler_load_dll()

            elif dbg_evt.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
                continue_status = self.event_handler_unload_dll()

            # an exception was caught.
            elif dbg_evt.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                ec = dbg_evt.u.Exception.ExceptionRecord.ExceptionCode

                if EXCEPTION_DEBUG_EVENT in self.callbacks:
                    self.callbacks[EXCEPTION_DEBUG_EVENT](self, ec)

                self._log(">>> evt(%.8X): exception: %.8X" % (self.dbg_evt.dwThreadId, ec))

                # call the internal handler for the exception event that just occured.
                if ec == EXCEPTION_ACCESS_VIOLATION:
                    continue_status = self.exception_handler_access_violation()
                elif ec == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif ec == EXCEPTION_GUARD_PAGE:
                    continue_status = self.exception_handler_guard_page()
                elif ec == EXCEPTION_SINGLE_STEP:
                    continue_status = self.exception_handler_single_step()
                # generic callback support.
                elif ec in self.callbacks:
                    continue_status = self.callbacks[ec](self)
                # unhandled exception.
                else:
                    if dbg_evt.u.Exception.dwFirstChance:
                        self._warn("[1st Chance] TID:%04x caused an unhandled exception (%08X - %s) at %08X " % (self.dbg_evt.dwThreadId, ec, msdn.resolve_code_exception(ec), self.exception_address))
                    else:
                        self._warn("[2nd Chance] TID:%04x caused an unhandled exception (%08X - %s) at %08X " % (self.dbg_evt.dwThreadId, ec, msdn.resolve_code_exception(ec), self.exception_address))

                    continue_status = DBG_EXCEPTION_NOT_HANDLED

            # OUTPUT_DEBUG_STRING_EVENT 8
            elif dbg_evt.dwDebugEventCode == 8:
                if self.dbg_evt.u.DebugString.fUnicode == 0:
                    dbg_str = "ansi...."
                else:
                    dbg_str = "unicode...."
                self._log("evt(%.8X): dbg string: %s" % (self.dbg_evt.dwThreadId, dbg_str))

                continue_status = DBG_EXCEPTION_NOT_HANDLED

            # RIP_EVENT 9
            elif dbg_evt.dwDebugEventCode == 9:
                self._log("evt(%.8X): rip, error: %d, type: %d" % (self.dbg_evt.dwThreadId, self.dbg_evt.u.RipInfo.dwError, self.dbg_evt.u.RipInfo.dwType))

                continue_status = DBG_CONTINUE

            else:
                self._high(">>> evt(%.8X): invalid" % (self.dbg_evt.dwThreadId))
                continue_status = DBG_EXCEPTION_NOT_HANDLED

            # if the memory space of the debuggee was tainted, flush the instruction cache.
            # from MSDN: Applications should call FlushInstructionCache if they generate or modify code in memory.
            #            The CPU cannot detect the change, and may execute the old code it cached.
            if self.dirty:
                kernel32.FlushInstructionCache(self.h_process, 0, 0)

            # close the opened thread handle and resume executing the thread that triggered the debug event.
            self.close_handle(self.h_thread)

            # !+ pydbg is command line utility, we surely don't need to pause it!!
            assert continue_status == DBG_CONTINUE or continue_status == DBG_EXCEPTION_NOT_HANDLED

        else:
            error = kernel32.GetLastError()
            if error == 121:

                # timeout, we take it as process termination(call api TerminateProcess() with h_proc as 0xFFFFFFFF, self-killing...)
                global v_tmp_is_treat_WaitForDebugEvent_as_termination
                if v_tmp_is_treat_WaitForDebugEvent_as_termination:
                    self._high("api(WaitForDebugEvent) time out, we take this as process termination")
                    self.event_handler_exit_process()
                else:
                    self._warn("api(WaitForDebugEvent) time out")
            else:
                self._high("api(WaitForDebugEvent) error: %d" % error)

        # TitanEngine, always call this whether WaitForDebugEvent() success or not. and if ContinueDebugEvent() fails, TitanEngine exit dbgloop.
        # TitanEngine.Debugger.DebugLoop.cpp
        if kernel32.ContinueDebugEvent(dbg_evt.dwProcessId, dbg_evt.dwThreadId, continue_status) == 0:
            error = kernel32.GetLastError()
            if error == 87:
                # self._warn("api(WaitForDebugEvent) invalid param")
                pass
            else:
                self._warn("api(ContinueDebugEvent) fail, error: %d" % error)

    def debug_event_loop(self):
        """
        Enter the infinite debug event handling loop.
        This is the main loop of the debugger and is responsible for catching debug events and exceptions and dispatching them appropriately.
        This routine will check for and call the USER_CALLBACK_DEBUG_EVENT callback on each loop iteration.
        run() is an alias for this routine.

        @raise pdx: An exception is raised on any exceptional conditions, such as debugger being interrupted or debuggee quiting.
        """

        while self.debugger_active:
            # don't let the user interrupt us in the midst of handling a debug event.
            try:
                def_sigint_handler = None
                def_sigint_handler = signal.signal(signal.SIGINT, self.sigint_handler)
            except:
                pass

            # if a user callback was specified, call it.
            if USER_CALLBACK_DEBUG_EVENT in self.callbacks:
                # user callbacks do not / should not access debugger or contextual information.
                self.dbg_evt = self.context = None
                self.callbacks[USER_CALLBACK_DEBUG_EVENT](self)

            # iterate through a debug event.
            self.debug_event_iteration()

            # resume keyboard interruptability.
            if def_sigint_handler:
                signal.signal(signal.SIGINT, def_sigint_handler)

        self._high("event loop exit")

        # close the global process handle.
        self.close_handle(self.h_process)

    def debug_set_process_kill_on_exit(self, kill_on_exit):
        """
        Convenience wrapper around DebugSetProcessKillOnExit().

        @param: kill_on_exit : bool : True to kill the process on debugger exit, False to let debuggee continue running.

        @raise pdx: An exception is raised on failure.
        """

        if not kernel32.DebugSetProcessKillOnExit(kill_on_exit):
            raise pdx("DebugActiveProcess(%s)" % kill_on_exit, True)

    def open_process(self, pid):
        """
        Convenience wrapper around OpenProcess().

        @param: pid : int : Process ID to attach to

        @return: int : process handle
        @raise pdx: An exception is raised on failure.
        """

        self.h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        if not self.h_process:
            raise pdx("OpenProcess(%d)" % pid, True)

        return self.h_process

    def open_thread(self, thread_id):
        """
        Convenience wrapper around OpenThread().

        @param: thread_id : int : ID of thread to obtain handle to

        @raise pdx: An exception is raised on failure.
        """

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if not h_thread:
            raise pdx("OpenThread(%d)" % thread_id, True)

        return h_thread

    # ---------------------------------------------------------------------------
    # evt handler
    def event_handler_create_process(self):
        """
        This is the default CREATE_PROCESS_DEBUG_EVENT handler.

        @return: int : Debug event continue status.
        """
        # don't need this.
        self.close_handle(self.dbg_evt.u.CreateProcessInfo.hFile)

        if not self.follow_forks:
            return DBG_CONTINUE

        if CREATE_PROCESS_DEBUG_EVENT in self.callbacks:
            return self.callbacks[CREATE_PROCESS_DEBUG_EVENT](self)
        else:
            return DBG_CONTINUE

    def event_handler_create_thread(self):
        """
        This is the default CREATE_THREAD_DEBUG_EVENT handler.

        @return: int : Debug event continue status.
        """
        # resolve the newly created threads TEB and add it to the internal dictionary.
        thread_id = self.dbg_evt.dwThreadId
        thread_handle = self.dbg_evt.u.CreateThread.hThread
        thread_context = self.get_thread_context(thread_handle)
        selector_entry = LDT_ENTRY()

        if not kernel32.GetThreadSelectorEntry(thread_handle, thread_context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        teb = selector_entry.BaseLow
        teb += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # add this TEB to the internal dictionary.
        self.tebs[thread_id] = teb

        #  apply any existing hardware breakpoints to this new thread.
        for slot, hw_bp in self.hardware_breakpoints.items():
            # mark available debug register as active (L0 - L3).
            thread_context.Dr7 |= 1 << (slot * 2)

            # save our breakpoint address to the available hw bp slot.
            if slot == 0:
                thread_context.Dr0 = hw_bp.address
            elif slot == 1:
                thread_context.Dr1 = hw_bp.address
            elif slot == 2:
                thread_context.Dr2 = hw_bp.address
            elif slot == 3:
                thread_context.Dr3 = hw_bp.address

            # set the condition (RW0 - RW3) field for the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
            thread_context.Dr7 |= hw_bp.condition << ((slot * 4) + 16)

            # set the length (LEN0-LEN3) field for the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
            thread_context.Dr7 |= hw_bp.length << ((slot * 4) + 18)

            # set the thread context.
            self.set_thread_context(thread_context, thread_id=thread_id)

        # pass control to user defined callback.
        if CREATE_THREAD_DEBUG_EVENT in self.callbacks:
            return self.callbacks[CREATE_THREAD_DEBUG_EVENT](self)
        else:
            return DBG_CONTINUE

    def event_handler_exit_process(self):
        """
        This is the default EXIT_PROCESS_DEBUG_EVENT handler.

        @raise pdx: An exception is raised to denote process exit.
        """

        self.set_debugger_active(False)

        if EXIT_PROCESS_DEBUG_EVENT in self.callbacks:
            return self.callbacks[EXIT_PROCESS_DEBUG_EVENT](self)
        else:
            return DBG_CONTINUE

    def event_handler_exit_thread(self):
        """
        This is the default EXIT_THREAD_DEBUG_EVENT handler.

        @return: int : Debug event continue status.
        """

        # before we remove the TEB entry from our internal list, let's give the user a chance to do something with it.
        if EXIT_THREAD_DEBUG_EVENT in self.callbacks:
            continue_status = self.callbacks[EXIT_THREAD_DEBUG_EVENT](self)
        else:
            continue_status = DBG_CONTINUE

        # remove the TEB entry for the exiting thread id.
        if self.dbg_evt.dwThreadId in self.tebs:
            del(self.tebs[self.dbg_evt.dwThreadId])

        return continue_status

    def event_handler_load_dll(self):
        """
        This is the default LOAD_DLL_DEBUG_EVENT handler.
        You can access the last loaded dll in your callback handler with the following example code::

            last_dll = pydbg.get_system_dll(-1)
            print "loading:%s from %s into:%08X  size:%d" % (last_dll.name, last_dll.path, last_dll.base, last_dll.size)

        The get_system_dll() routine is preferred over directly accessing the internal data structure for proper and transparent client/server support.

        @return: int : Debug event continue status.
        """
        dll = SystemDll(self.dbg_evt.u.LoadDll.hFile, self.dbg_evt.u.LoadDll.lpBaseOfDll)
        for sys_dll in self.system_dlls:
            if sys_dll.is_same_sys_dll(dll):
                self._warn("reloading same dll for unknown reason, negelect it: %s" % dll)
                return DBG_CONTINUE

        self.system_dlls.append(dll)
        self._log(">>> evt(%.8X): load dll: %s" % (self.dbg_evt.dwThreadId, dll.name))

        if LOAD_DLL_DEBUG_EVENT in self.callbacks:
            return self.callbacks[LOAD_DLL_DEBUG_EVENT](self)
        else:
            return DBG_CONTINUE

    def event_handler_unload_dll(self):
        """
        This is the default UNLOAD_DLL_DEBUG_EVENT handler.

        @return: int : Debug event continue status.
        """

        base = self.dbg_evt.u.UnloadDll.lpBaseOfDll
        unloading = None

        for system_dll in self.system_dlls:
            if system_dll.base == base:
                unloading = system_dll
                self._log(">>> evt(%.8X): unload dll: %s" % (self.dbg_evt.dwThreadId, unloading.name))
                break

        # before we remove the system dll from our internal list, let's give the user a chance to do something with it.
        if UNLOAD_DLL_DEBUG_EVENT in self.callbacks:
            continue_status = self.callbacks[UNLOAD_DLL_DEBUG_EVENT](self)
        else:
            continue_status = DBG_CONTINUE

        if not unloading:
            # raise pdx("Unable to locate DLL that is being unloaded from %08X " % base, False)
            self._high("Unable to locate DLL that is being unloaded from %.8X " % base)
        else:
            # close the open file handle to the system dll being unloaded.
            self.close_handle(unloading.handle)

            # remove the system dll from the internal list.
            self.system_dlls.remove(unloading)
            del(unloading)

        return continue_status

    # ---------------------------------------------------------------------------
    # excep handler
    def exception_handler_access_violation(self):
        """
        This is the default EXCEPTION_ACCESS_VIOLATION handler.
        Responsible for handling the access violation and passing control to the registered user callback handler.

        @attention: If you catch an access violaton and wish to terminate the process, you *must* still return DBG_CONTINUE to avoid a deadlock.

        @return: int : Debug event continue status.
        """

        if EXCEPTION_ACCESS_VIOLATION in self.callbacks:
            return self.callbacks[EXCEPTION_ACCESS_VIOLATION](self)
        else:
            return DBG_EXCEPTION_NOT_HANDLED

    def exception_handler_breakpoint(self):
        """
        This is the default EXCEPTION_BREAKPOINT handler, responsible for transparently restoring soft breakpoints and passing control to the registered user callback handler.

        @return: int : Debug event continue status.
        """
        # breakpoints we did not set.
        if not self.bp_is_ours(self.exception_address):
            # system breakpoints.
            if self.exception_address == self.system_break:
                # pass control to user registered call back.
                if EXCEPTION_BREAKPOINT in self.callbacks:
                    continue_status = self.callbacks[EXCEPTION_BREAKPOINT](self)
                else:
                    continue_status = DBG_CONTINUE

                if self.first_breakpoint:
                    self._log("first windows driven system breakpoint at %08X " % self.exception_address)
                    self.first_breakpoint = False

            # ignore all other breakpoints we didn't explicitly set.
            else:
                self._log("breakpoint not ours %08X " % self.exception_address)
                continue_status = DBG_EXCEPTION_NOT_HANDLED

        # breakpoints we did set.
        else:
            # restore the original byte at the breakpoint address.
            # self._log("restoring original byte at %08X " % self.exception_address)
            self._write_process_memory(self.exception_address, self.breakpoints[self.exception_address].original_byte)
            self.set_attr("dirty", True)

            # before we can continue, we have to correct the value of EIP.
            # the reason for this is that the 1-byte INT 3 we inserted causes EIP to "slide" + 1 into the original instruction and must be reset.
            self.set_register("EIP", self.exception_address)
            self.context.Eip -= 1

            # if there is a specific handler registered for this bp, pass control to it.
            if self.breakpoints[self.exception_address].handler:
                # self._log("calling user handler")
                continue_status = self.breakpoints[self.exception_address].handler(self)

            # pass control to default user registered call back handler, if it is specified.
            elif EXCEPTION_BREAKPOINT in self.callbacks:
                continue_status = self.callbacks[EXCEPTION_BREAKPOINT](self)

            else:
                continue_status = DBG_CONTINUE

            # if the breakpoint still exists, ie: the user didn't erase it during the callback, and the breakpoint is flagged for restore, then tell the single step handler about it.
            # furthermore, check if the debugger is still active, that way we don't try and single step if the user requested a detach.
            if self.get_attr("debugger_active") and self.exception_address in self.breakpoints:
                if self.breakpoints[self.exception_address].restore:
                    self._restore_breakpoint = self.breakpoints[self.exception_address]
                    self.single_step(True)

                self.bp_del(self.exception_address)

        return continue_status

    def exception_handler_guard_page(self):
        """
        This is the default EXCEPTION_GUARD_PAGE handler, responsible for transparently restoring memory breakpoints passing control to the registered user callback handler.

        @return: int : Debug event continue status.
        """
        # determine the base address of the page where the offending reference resides.
        mbi = self.virtual_query(self.violation_address)

        # if the hit is on a page we did not explicitly GUARD, then pass the violation to the debuggee.
        if mbi.BaseAddress not in self._guarded_pages:
            return DBG_EXCEPTION_NOT_HANDLED

        # determine if the hit was within a monitored buffer, or simply on the same page.
        self.memory_breakpoint_hit = self.bp_is_ours_mem(self.violation_address)

        # grab the actual memory breakpoint object, for the hit breakpoint.
        if self.memory_breakpoint_hit:
            self._log("direct hit on memory breakpoint at %08X " % self.memory_breakpoint_hit)

        if self.write_violation:
            self._log("write violation from %08X  on %08X  of mem bp" % (self.exception_address, self.violation_address))
        else:
            self._log("read violation from %08X  on %08X  of mem bp" % (self.exception_address, self.violation_address))

        # if there is a specific handler registered for this bp, pass control to it.
        if self.memory_breakpoint_hit and self.memory_breakpoints[self.memory_breakpoint_hit].handler:
            continue_status = self.memory_breakpoints[self.memory_breakpoint_hit].handler(self)

        # pass control to default user registered call back handler, if it is specified.
        elif EXCEPTION_GUARD_PAGE in self.callbacks:
            continue_status = self.callbacks[EXCEPTION_GUARD_PAGE](self)

        else:
            continue_status = DBG_CONTINUE

        # if the hit page is still in our list of explicitly guarded pages, ie: the user didn't erase it during the
        # callback, then tell the single step handler about it. furthermore, check if the debugger is still active,
        # that way we don't try and single step if the user requested a detach.
        if self.get_attr("debugger_active") and mbi.BaseAddress in self._guarded_pages:
            self._restore_breakpoint = memory_breakpoint(None, None, mbi, None)
            self.single_step(True)

        return continue_status

    def exception_handler_single_step(self):
        """
        This is the default EXCEPTION_SINGLE_STEP handler, responsible for transparently restoring breakpoints and passing control to the registered user callback handler.

        @return: int : Debug event continue status.
        """
        # if there is a breakpoint to restore.
        if self._restore_breakpoint:
            bp = self._restore_breakpoint

            # restore a soft breakpoint.
            if isinstance(bp, breakpoint):
                self._log("restoring breakpoint at %08X " % bp.address)
                self.bp_set(bp.address, bp.description, bp.restore, bp.handler)

            # restore PAGE_GUARD for a memory breakpoint (make sure guards are not temporarily suspended).
            elif isinstance(bp, memory_breakpoint) and self._guards_active:
                self._log("restoring %08X  +PAGE_GUARD on page based @ %08X " % (bp.mbi.Protect, bp.mbi.BaseAddress))
                self.virtual_protect(bp.mbi.BaseAddress, 1, bp.mbi.Protect | PAGE_GUARD)

            # restore a hardware breakpoint.
            elif isinstance(bp, hardware_breakpoint):
                self._log("restoring hardware breakpoint on %08X " % bp.address)
                self.bp_set_hw(bp.address, bp.length, bp.condition, bp.description, bp.restore, bp.handler)

        # determine if this single step event occured in reaction to a hardware breakpoint and grab the hit breakpoint.
        # according to the Intel docs, we should be able to check for the BS flag in Dr6. but it appears that windows
        # isn't properly propogating that flag down to us.
        if self.context.Dr6 & 0x1 and 0 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[0]

        elif self.context.Dr6 & 0x2 and 1 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[1]

        elif self.context.Dr6 & 0x4 and 2 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[2]

        elif self.context.Dr6 & 0x8 and 3 in self.hardware_breakpoints:
            self.hardware_breakpoint_hit = self.hardware_breakpoints[3]

        # if we are dealing with a hardware breakpoint and there is a specific handler registered, pass control to it.
        if self.hardware_breakpoint_hit and self.hardware_breakpoint_hit.handler:
            continue_status = self.hardware_breakpoint_hit.handler(self)

        # pass control to default user registered call back handler, if it is specified.
        elif EXCEPTION_SINGLE_STEP in self.callbacks:
            continue_status = self.callbacks[EXCEPTION_SINGLE_STEP](self)

        # if we single stepped to handle a breakpoint restore.
        elif self._restore_breakpoint:
            continue_status = DBG_CONTINUE

            # macos compatability.
            # need to clear TRAP flag for MacOS. this doesn't hurt Windows aside from a negligible speed hit.
            context = self.get_thread_context(self.h_thread)
            context.EFlags &= ~EFLAGS_TRAP
            self.set_thread_context(context)

        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        # if we are handling a hardware breakpoint hit and it still exists, ie: the user didn't erase it during the
        # callback, and the breakpoint is flagged for restore, then tell the single step handler about it. furthermore,
        # check if the debugger is still active, that way we don't try and single step if the user requested a detach.
        if self.hardware_breakpoint_hit is not None and self.get_attr("debugger_active"):
            slot = self.hardware_breakpoint_hit.slot

            if slot in self.hardware_breakpoints:
                curr = self.hardware_breakpoints[slot]
                prev = self.hardware_breakpoint_hit

                if curr.address == prev.address:
                    if prev.restore:
                        self._restore_breakpoint = prev
                        self.single_step(True)

                    self.bp_del_hw(slot=prev.slot)

        # reset the hardware breakpoint hit flag and restore breakpoint variable.
        self.hardware_breakpoint_hit = None
        self._restore_breakpoint = None

        return continue_status

    # ---------------------------------------------------------------------------
    # retrive
    def retrive_ascii_string(self, data):
        """
        Retrieve the ASCII string, if any, from data.
        Ensure that the string is valid by checking against the minimum length requirement defined in self.STRING_EXPLORATION_MIN_LENGTH.

        @param: data : raw : Data to explore for printable ascii string

        @return: string : ascii string on discovered string.
               : False  : failure
        """
        discovered = ""

        for char in data:
            # if we've hit a non printable char, break
            if ord(char) < 32 or ord(char) > 126:
                break

            discovered += char

        if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
            return False

        return discovered

    def is_char_printable(self, char):
        return ord(char) >= 32 and ord(char) <= 126

    def retrive_printable_string(self, data, print_dots=True):
        """
        description

        @param: data       : raw  : Data to explore for printable ascii string
        @param: print_dots : bool : (Optional, def:True) Controls suppression of dot in place of non-printable

        @return: string : discovered printable chars in string otherwise.
               : False  : failure,
        """
        discovered = ""

        for char in data:
            if self.is_char_printable(char):
                discovered += char
            elif print_dots:
                discovered += "."

        return discovered

    # ---------------------------------------------------------------------------
    # read

    def _read_process_memory(self, addr, length):
        """
        Read from the debuggee process space.

        @param: addr             : int  : Address to read from.
        @param: length              : int  : Length, in bytes, of data to read.

        @return: raw :
        @raise pdx: An exception is raised on failure.
        """
        # todo: check if addr valid first
        if addr == 0:
            return ""

        data = ""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        # orig_length = length
        # orig_address = addr

        # ensure we can read from the requested memory space.
        _address = addr
        _length = length

        try:
            # self._log("read_process_memory -> virtual_protect: %X - %X" % (_address, _length))
            old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            # we skip reading....
            # self._high("protect mm fail, addr: %.8X, len: %.8X" % (_address, _length))
            return ""

        while length:
            if not kernel32.ReadProcessMemory(self.h_process, addr, read_buf, length, byref(count)):
                if not len(data):
                    raise pdx("ReadProcessMemory(%08X , %d, read=%d)" % (addr, length, count.value), True)
                else:
                    return data

            data += read_buf.raw
            length -= count.value
            addr += count.value

        # restore the original page permissions on the target memory region.
        try:
            self.virtual_protect(_address, _length, old_protect)
        except:
            pass

        return data

    def read_func_arg(self, index, context=None):
        """
        Given a thread context, this convenience routine will retrieve the function argument at the specified index.
        The return address of the function can be retrieved by specifying an index of 0.

        @param: index   : int     : Data to explore for printable ascii string
        @param: context : Context : (Optional) Current thread context to examine

        @rtype:  DWORD
        @return: Value of specified argument.

        !+ This routine should be called from breakpoint handlers at the top of a function.
        """
        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        arg_val = self._read_process_memory(context.Esp + index * 4, 4)
        arg_val = self.flip_endian_dword(arg_val)

        return arg_val

    def read_instruction(self, addr):
        """
        Pydasm disassemble utility function wrapper. Returns the pydasm decoded instruction in self.instruction.

        @param: addr : int : Address to disassemble at

        @return: pydasm instruction
        """
        try:
            data = self._read_process_memory(addr, 32)
        except:
            return "Unable to disassemble at %08X " % addr

        if data is not None and len(data) > 1:
            return pydasm.get_instruction(data, pydasm.MODE_32)
        return None

    # ---------------------------------------------------------------------------
    # write

    def _write_process_memory(self, addr, data, length=0):
        """
        Write to the debuggee process space. Convenience wrapper around WriteProcessMemory().
        This routine will continuously attempt to write the data requested until it is complete.

        @param: addr : int : Address to write to
        @param: data    : raw : Data to write
        @param: length  : int : (Optional, Def:len(data)) Length of data, in bytes, to write

        @raise pdx: An exception is raised on failure.
        """

        count = c_ulong(0)

        # if the optional data length parameter was omitted, calculate the length ourselves.
        if not length:
            length = len(data)

        # ensure we can write to the requested memory space.
        _address = addr
        _length = length
        try:
            # self._log("write_process_memory -> virtual_protect 1")
            old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            pass

        while length:
            c_data = c_char_p(data[count.value:])

            if not kernel32.WriteProcessMemory(self.h_process, addr, c_data, length, byref(count)):
                raise pdx("WriteProcessMemory(%08X , ..., %d)" % (addr, length), True)

            length -= count.value
            addr += count.value

        # restore the original page permissions on the target memory region.
        try:
            # self._log("write_process_memory -> virtual_protect 2")
            self.virtual_protect(_address, _length, old_protect)
        except:
            pass

    # ---------------------------------------------------------------------------
    # 使用 _util.util 里面的各种 read_xx() write_xx() 读写内存

    def get_esp(self):
        return self.context.Esp

    def read(self, addr, length):
        """
        Alias to read_process_memory().
        """
        return self._read_process_memory(addr, length)

    def write(self, addr, data, length=0):
        """
        Alias to write_process_memory().
        """
        return self._write_process_memory(addr, data, length)

    # ---------------------------------------------------------------------------
    # system dll
    def check_has_system_dll(self, dll_name):
        """
            check process has specified system dll by name

            @param: dll_name : string : dll name to check

            @return: bool :
        """
        dll_name = dll_name.lower()

        for sys_dll in self.system_dlls:
            if sys_dll.name == dll_name:
                return True

        return False

    def get_system_dll(self, idx):
        """
        Return the system DLL at the specified index. If the debugger is in client / server mode, remove the PE structure (we do not want to send that mammoth over the wire).

        @param: idx : int : Index into self.system_dlls[] to retrieve DLL from.

        @return: Mixed : Requested attribute or None if not found.
        """

        self._log("get_system_dll()")

        try:
            dll = self.system_dlls[idx]
        except:
            # index out of range.
            return None

        dll.pe = None
        return dll

    def get_sys_dll_names(self):
        """
            get system dll names

            @return: list :
        """
        ret = []
        for sys_dll in self.system_dlls:
            ret.append(sys_dll.name)
        return ret

    # ---------------------------------------------------------------------------
    def page_guard_clear(self):
        """
        Clear all debugger-set PAGE_GUARDs from memory.
        This is useful for suspending memory breakpoints to single step past a REP instruction.

        @return: self :
        """

        self._guards_active = False

        for page in self._guarded_pages:
            # make a best effort, let's not crash on failure though.
            try:
                mbi = self.virtual_query(page)
                self.virtual_protect(mbi.BaseAddress, 1, mbi.Protect & ~PAGE_GUARD)
            except:
                pass

        return self.ret_self()

    def get_debug_privileges(self):
        """
        Obtain necessary privileges for debugging.

        @raise pdx: An exception is raised on failure.
        """

        h_token = HANDLE()
        luid = LUID()
        token_state = TOKEN_PRIVILEGES()

        self._log("get_debug_privileges()")

        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, byref(h_token)):
            raise pdx("OpenProcessToken()", True)

        if not advapi32.LookupPrivilegeValueA(0, "seDebugPrivilege", byref(luid)):
            raise pdx("LookupPrivilegeValue()", True)

        token_state.PrivilegeCount = 1
        token_state.Privileges[0].Luid = luid
        token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not advapi32.AdjustTokenPrivileges(h_token, 0, byref(token_state), 0, 0, 0):
            raise pdx("AdjustTokenPrivileges()", True)

    def hex_dump(self, data, addr=0, prefix=""):
        """
        Utility function that converts data into hex dump format.

        @param: data   : raw    : Raw bytes to view in hex dump
        @param: addr   : int    : (Optional, def=0) Address to start hex offset display from
        @param: prefix : string : (Optional, def="")String to prefix each line of hex dump with.

        @return: string : Hex dump of data.
        """
        dump = prefix
        slice = ""

        for byte in data:
            if addr % 16 == 0:
                dump += " "

                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."

                dump += "\n%s%04x: " % (prefix, addr)
                slice = ""

            dump += "%02x " % ord(byte)
            slice += byte
            addr += 1

        remainder = addr % 16

        if remainder != 0:
            dump += "   " * (16 - remainder) + " "

        for char in slice:
            if ord(char) >= 32 and ord(char) <= 126:
                dump += char
            else:
                dump += "."

        return dump + "\n"

    # ---------------------------------------------------------------------------
    def page_guard_restore(self):
        """
        Restore all previously cleared debugger-set PAGE_GUARDs from memory.
        This is useful for suspending memory breakpoints to single step past a REP instruction.

        @return: self :
        """

        self._guards_active = True

        for page in self._guarded_pages:
            # make a best effort, let's not crash on failure though.
            try:
                mbi = self.virtual_query(page)
                self.virtual_protect(mbi.BaseAddress, 1, mbi.Protect | PAGE_GUARD)
            except:
                pass

        return self.ret_self()

    # ---------------------------------------------------------------------------
    def pid_to_port(self, pid):
        """
        A helper function that enumerates the IPv4 endpoints for a given process ID.

        @param: pid : int : Process ID to find port information on.

        @rtype:     A list of tuples
        @return:    A list of the protocol, bound addr and listening port
        @raise pdx: An exception is raised on failure
        """

        # local variables to hold all our necessary sweetness.
        listening_port = None
        bound_address = None
        protocol = None
        port_list = []
        tcp_table = MIB_TCPTABLE_OWNER_PID()
        udp_table = MIB_UDPTABLE_OWNER_PID()
        init_size = c_int()

        # TCP ENDPOINTS

        # the first run is to determine the sizing of the struct.
        size_result = iphlpapi.GetExtendedTcpTable(byref(tcp_table),
                                                   byref(init_size),
                                                   False,
                                                   AF_INET,
                                                   TCP_TABLE_OWNER_PID_ALL,
                                                   0)

        if not size_result:
            raise pdx("Couldn't retrieve extended TCP information for PID: %d" % pid, True)

        # retrieve the table of TCP_ROW structs, with the correct size this time.
        # reslt = iphlpapi.GetExtendedTcpTable(byref(tcp_table),
        #                                      byref(init_size),
        #                                      False,
        #                                      AF_INET,
        #                                      TCP_TABLE_OWNER_PID_ALL,
        #                                      0)
        iphlpapi.GetExtendedTcpTable(byref(tcp_table),
                                     byref(init_size),
                                     False,
                                     AF_INET,
                                     TCP_TABLE_OWNER_PID_ALL,
                                     0)
        # step through the entries. we only want ports that have the listening flag set. snag the port, addr and
        # protocol tuple and add it to port_list.
        for i in xrange(tcp_table.dwNumEntries):
            if tcp_table.table[i].dwOwningPid == pid:
                if tcp_table.table[i].dwState == MIB_TCP_STATE_LISTEN:
                    listening_port = "%d" % socket.ntohs(tcp_table.table[i].dwLocalPort)
                    bound_address = socket.inet_ntoa(struct.pack("L", tcp_table.table[i].dwLocalAddr))
                    protocol = "TCP"

                    port_list.append((protocol, bound_address, listening_port))

        # UDP ENDPOINTS

        # NOTE: An application can bind a UDP port explicitly to send datagrams, this may not be 100% accurate
        # so we only take into account those UDP sockets which are bound in a manner that allows datagrams on any
        # interface.
        init_size = c_int(0)
        # size_resuld = iphlpapi.GetExtendedUdpTable(byref(udp_table),
        #                                            byref(init_size),
        #                                            False,
        #                                            AF_INET,
        #                                            UDP_TABLE_OWNER_PID,
        #                                            0)
        iphlpapi.GetExtendedUdpTable(byref(udp_table),
                                     byref(init_size),
                                     False,
                                     AF_INET,
                                     UDP_TABLE_OWNER_PID,
                                     0)
        # retrieve the table of UDP_ROW structs.
        if not size_result:
            raise pdx("Couldn't retrieve extended UDP information for PID: %d" % pid, True)

        # result = iphlpapi.GetExtendedUdpTable(byref(udp_table),
        #                                       byref(init_size),
        #                                       False,
        #                                       AF_INET,
        #                                       UDP_TABLE_OWNER_PID,
        #                                       0)
        iphlpapi.GetExtendedUdpTable(byref(udp_table),
                                     byref(init_size),
                                     False,
                                     AF_INET,
                                     UDP_TABLE_OWNER_PID,
                                     0)
        for i in range(udp_table.dwNumEntries):
            if udp_table.table[i].dwOwningPid == pid:
                # if the local addr is 0 then it is a listening socket accepting datagrams.
                if udp_table.table[i].dwLocalAddr == 0:
                    listening_port = "%d" % socket.ntohs(udp_table.table[i].dwLocalPort)
                    bound_address = socket.inet_ntoa(struct.pack("L", udp_table.table[i].dwLocalAddr))
                    protocol = "UDP"

                    port_list.append((protocol, bound_address, listening_port))

        return port_list

    # ---------------------------------------------------------------------------
    def process_restore(self):
        """
        Restore memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.

        @return: self :
        """

        # fetch the current list of threads.
        current_thread_list = self.enumerate_threads()

        # restore the thread context for threads still active.
        for thread_context in self.memory_snapshot_contexts:
            if thread_context.thread_id in current_thread_list:
                self.set_thread_context(thread_context.context, thread_id=thread_context.thread_id)

        # restore all saved memory blocks.
        for memory_block in self.memory_snapshot_blocks:
            try:
                self._write_process_memory(memory_block.mbi.BaseAddress, memory_block.data, memory_block.mbi.RegionSize)
            except pdx, x:
                self._err("-- IGNORING ERROR --")
                self._err("process_restore: " + x.__str__().rstrip("\r\n"))
                pass

        return self.ret_self()

    # ---------------------------------------------------------------------------
    def process_snapshot(self, mem_only=False):
        """
        Take memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.

        @return: self :
        """

        self._log("taking debuggee snapshot")

        do_not_snapshot = [PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS]
        cursor = 0

        # reset the internal snapshot data structure lists.
        self.memory_snapshot_blocks = []
        self.memory_snapshot_contexts = []

        if not mem_only:
            # enumerate the running threads and save a copy of their contexts.
            for thread_id in self.enumerate_threads():
                context = self.get_thread_context(None, thread_id)

                self.memory_snapshot_contexts.append(memory_snapshot_context(thread_id, context))

                self._log("saving thread context of thread id: %08X " % thread_id)

        # scan through the entire memory range and save a copy of suitable memory blocks.
        while cursor < 0xFFFFFFFF:
            save_block = True

            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            # do not snapshot blocks of memory that match the following characteristics.
            # XXX - might want to drop the MEM_IMAGE check to accomodate for self modifying code.
            if mbi.State != MEM_COMMIT or mbi.Type == MEM_IMAGE:
                save_block = False

            for has_protection in do_not_snapshot:
                if mbi.Protect & has_protection:
                    save_block = False
                    break

            if save_block:
                self._log("Adding %08X  +%d to memory snapsnot." % (mbi.BaseAddress, mbi.RegionSize))

                # read the raw bytes from the memory block.
                data = self._read_process_memory(mbi.BaseAddress, mbi.RegionSize)

                self.memory_snapshot_blocks.append(memory_snapshot_block(mbi, data))

            cursor += mbi.RegionSize

        return self.ret_self()

    # ---------------------------------------------------------------------------
    def resume_all_threads(self):
        """
        Resume all process threads.

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        for thread_id in self.enumerate_threads():
            self.resume_thread(thread_id)

        return self.ret_self()

    # ---------------------------------------------------------------------------
    def resume_thread(self, thread_id):
        """
        Resume the specified thread.

        @param: thread_id : int : ID of thread to resume.

        @raise pdx: An exception is raised on failure.

        @return: self :
        """

        self._log("resuming thread: %08X " % thread_id)

        thread_handle = self.open_thread(thread_id)

        if kernel32.ResumeThread(thread_handle) == -1:
            raise pdx("ResumeThread()", True)

        self.close_handle(thread_handle)

        return self.ret_self()

    # ---------------------------------------------------------------------------
    def ret_self(self):
        """
        This convenience routine exists for internal functions to call and transparently return the correct version of self.
        Specifically, an object in normal mode and a moniker when in client/server mode.

        @return: Client / server safe version of self
        """
        if self.client_server:
            return "**SELF**"
        else:
            return self

    # ---------------------------------------------------------------------------
    def seh_unwind(self, context=None):
        """
        Unwind the the Structured Exception Handler (SEH) chain of the current or specified thread to the best of our abilities.
        The SEH chain is a simple singly linked list, the head of which is pointed to by fs:0.
        In cases where the SEH chain is corrupted and the handler addr points to invalid memory, it will be returned as 0xFFFFFFFF.

        @param: context : Context : (Optional) Current thread context to examine

        @rtype:  List of Tuples
        @return: Naturally ordered list of SEH addresses and handlers.
        """

        self._log("seh_unwind()")

        selector_entry = LDT_ENTRY()
        seh_chain = []

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        if not kernel32.GetThreadSelectorEntry(self.h_thread, context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        fs_base = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # determine the head of the current threads SEH chain.
        seh_head = self._read_process_memory(fs_base, 4)
        seh_head = self.flip_endian_dword(seh_head)

        while seh_head != 0xFFFFFFFF:
            try:
                handler = self._read_process_memory(seh_head + 4, 4)
                handler = self.flip_endian_dword(handler)
            except:
                handler = 0xFFFFFFFF

            try:
                seh_head = self._read_process_memory(seh_head, 4)
                seh_head = self.flip_endian_dword(seh_head)
            except:
                seh_head = 0xFFFFFFFF

            seh_chain.append((seh_head, handler))

        return seh_chain

    # ---------------------------------------------------------------------------
    def set_attr(self, attribute, value):
        """
        Return the value for the specified class attribute.
        This routine should be used over directly accessing class member variables for transparent support across local vs. client/server debugger clients.

        @param: attribute : string : Name of attribute to return.
        @param: value     : Mixed  : Value to set attribute to.
        """
        if hasattr(self, attribute):
            setattr(self, attribute, value)

    # ---------------------------------------------------------------------------
    def set_callback(self, exception_code, callback_func):
        """
        Set a callback for the specified exception (or debug event) code. The prototype of the callback routines is::

            func (pydbg):
                return DBG_CONTINUE     # or other continue status

        You can register callbacks for any exception code or debug event.
        Look in the source for all event_handler_??? and exception_handler_??? routines to see which ones have internal processing (internal handlers will still pass control to your callback).
        You can also register a user specified callback that is called on each loop iteration from within debug_event_loop().
        The callback code is USER_CALLBACK_DEBUG_EVENT and the function prototype is::

            func (pydbg)
                return DBG_CONTINUE     # or other continue status

        User callbacks do not / should not access debugger or contextual information.

        @param: exception_code : long   : Exception code to establish a callback for
        @param: callback_func  : method : Function to call when specified exception code is caught.
        """
        self.callbacks[exception_code] = callback_func

    # ---------------------------------------------------------------------------
    def set_debugger_active(self, enable):
        """
        Enable or disable the control flag for the main debug event loop. This is a convenience shortcut over set_attr.

        @param: enable : bool : Flag controlling the main debug event loop.
        """

        self._log("setting debug event loop flag to %s" % enable)
        self.debugger_active = enable

    # ---------------------------------------------------------------------------
    def sigint_handler(self, signal_number, stack_frame):
        """
        Interrupt signal handler. We override the default handler to disable the run flag and exit the main debug event loop.

        @param: signal_number:
        @param: stack_frame:
        """
        self.set_debugger_active(False)

    # ---------------------------------------------------------------------------
    def single_step(self, enable, thread_handle=None):
        """
        Enable or disable single stepping in the specified thread or self.h_thread if a thread handle is not specified.

        @param: enable        : bool   : True to enable single stepping, False to disable
        @param: thread_handle : Handle : (Optional, Def=None) Handle of thread to put into single step mode

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        self._log("single_step(%s)" % enable)

        if not thread_handle:
            thread_handle = self.h_thread

        context = self.get_thread_context(thread_handle)

        if enable:
            # single step already enabled.
            if context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags |= EFLAGS_TRAP
        else:
            # single step already disabled:
            if not context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags = context.EFlags & (0xFFFFFFFFFF ^ EFLAGS_TRAP)

        self.set_thread_context(context, thread_handle=thread_handle)

        return self.ret_self()

    # ---------------------------------------------------------------------------
    def smart_dereference(self, addr, print_dots=True, hex_dump=False):
        """
        "Intelligently" discover data behind an address.
        The address is dereferenced and explored in search of an ASCII or Unicode string.
        In the absense of a string the printable characters are returned with non-printables represented as dots (.).
        The location of the discovered data is returned as well as either "heap", "stack" or the name of the module it lies in (global data).

        @param: addr    : int  : Address to smart dereference
        @param: print_dots : bool : (Optional, def:True) Controls suppression of dot in place of non-printable
        @param: hex_dump   : bool : (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  String
        @return: String of data discovered behind dereference.
        """

        try:
            mbi = self.virtual_query(addr)
        except:
            return "N/A"

        # if the addr doesn't point into writable memory (stack or heap), then bail.
        if not mbi.Protect & PAGE_READWRITE:
            return "N/A"

        # if the addr does point to writeable memory, ensure it doesn't sit on the PEB or any of the TEBs.
        if mbi.BaseAddress == self.peb or mbi.BaseAddress in self.tebs.values():
            return "N/A"

        try:
            explored = self._read_process_memory(addr, self.STRING_EXPLORATON_BUF_SIZE)
        except:
            return "N/A"

        # determine if the write-able addr sits in the stack range.
        if self.is_address_on_stack(addr):
            location = "stack"

        # otherwise it could be in a module's global section or on the heap.
        else:
            module = self.addr_to_module(addr)

            if module:
                location = "%s.data" % module.szModule

            # if the write-able addr is not on the stack or in a module range, then we assume it's on the heap.
            # we *could* walk the heap structures to determine for sure, but it's a slow method and this process of
            # elimination works well enough.
            else:
                location = "heap"

        explored_string = self.retrive_ascii_string(explored)

        if not explored_string:
            explored_string = self.retrive_unicode_string(explored)

        if not explored_string and hex_dump:
            explored_string = self.hex_dump(explored)

        if not explored_string:
            explored_string = self.retrive_printable_string(explored, print_dots)

        if hex_dump:
            return "%s --> %s" % (explored_string, location)
        else:
            return "%s (%s)" % (explored_string, location)

    # ---------------------------------------------------------------------------
    def stack_range(self, context=None):
        """
        Determine the stack range (top and bottom) of the current or specified thread.
        The desired information is located at offsets 4 and 8 from the Thread Environment Block (TEB), which in turn is pointed to by fs:0.

        @param: context : Context : (Optional) Current thread context to examine

        @return: Mixed : List containing (stack_top, stack_bottom) on success, False otherwise.
        """

        selector_entry = LDT_ENTRY()

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        if not kernel32.GetThreadSelectorEntry(self.h_thread, context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        fs_base = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # determine the top and bottom of the debuggee's stack.
        stack_top = self._read_process_memory(fs_base + 4, 4)
        stack_bottom = self._read_process_memory(fs_base + 8, 4)

        stack_top = self.flip_endian_dword(stack_top)
        stack_bottom = self.flip_endian_dword(stack_bottom)

        return (stack_top, stack_bottom)

    # ---------------------------------------------------------------------------
    def stack_unwind(self, context=None):
        """
        Unwind the stack to the best of our ability.
        This function is really only useful if called when EBP is actually used as a frame pointer.
        If it is otherwise being used as a general purpose register then stack unwinding will fail immediately.

        @param: context : Context : (Optional) Current thread context to examine

        @return: list : The current call stack ordered from most recent call backwards.
        """
        self._log("stack_unwind()")

        # selector_entry = LDT_ENTRY()
        StackFrame = []

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        # determine the stack top / bottom.
        (stack_top, stack_bottom) = self.stack_range(context)

        this_frame = context.Ebp

        while this_frame > stack_bottom and this_frame < stack_top:
            # stack frame sanity check: must be DWORD boundary aligned.
            if this_frame & 3:
                break

            try:
                ret_addr = self._read_process_memory(this_frame + 4, 4)
                ret_addr = self.flip_endian_dword(ret_addr)
            except:
                break

            # return addr sanity check: return addr must live on an executable page.
            try:
                mbi = self.virtual_query(ret_addr)
            except:
                break

            if mbi.Protect not in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
                break

            # add the return addr to the call stack.
            StackFrame.append(ret_addr)

            # follow the frame pointer to the next frame.
            try:
                next_frame = self._read_process_memory(this_frame, 4)
                next_frame = self.flip_endian_dword(next_frame)
            except:
                break

            # stack frame sanity check: new frame must be at a higher addr then the previous frame.
            if next_frame <= this_frame:
                break

            this_frame = next_frame

        return StackFrame

    # ---------------------------------------------------------------------------
    def suspend_all_threads(self):
        """
        Suspend all process threads.

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        for thread_id in self.enumerate_threads():
            self.suspend_thread(thread_id)

        return self.ret_self()

    def suspend_thread(self, thread_id):
        """
        Suspend the specified thread.

        @param: thread_id : int : ID of thread to suspend

        @return: self :
        @raise pdx: An exception is raised on failure.
        """
        self._log("suspending thread: %08X " % thread_id)

        thread_handle = self.open_thread(thread_id)

        if kernel32.SuspendThread(thread_handle) == -1:
            raise pdx("SuspendThread()", True)

        self.close_handle(thread_handle)

        return self.ret_self()

    # ---------------------------------------------------------------------------
    def to_binary(self, number, bit_count=32):
        """
        Convert a number into a binary string.
        This is an ugly one liner that I ripped off of some site.

        @param: number    : int : Number to convert to binary string.
        @param: bit_count : int : (Optional, Def=32) Number of bits to include in output string.

        @return: string : Specified integer as a binary string
        """
        return "".join(map(lambda x: str((number >> x) & 1), range(bit_count - 1, -1, -1)))

    # ---------------------------------------------------------------------------
    def to_decimal(self, binary):
        """
        Convert a binary string into a decimal number.

        @param: binary : string : Binary string to convert to decimal

        @return: int : Specified binary string as an integer
        """

        # this is an ugly one liner that I ripped off of some site.
        # return sum(map(lambda x: int(binary[x]) and 2**(len(binary) - x - 1), range(len(binary)-1, -1, -1)))

        # this is much cleaner (thanks cody)
        return int(binary, 2)

    # ---------------------------------------------------------------------------
    # mm
    def virtual_alloc(self, addr, size, alloc_type, protection):
        """
        Convenience wrapper around VirtualAllocEx()

        @param: addr    : int : Desired starting addr of region to allocate, can be None
        @param: size       : int : Size of memory region to allocate, in bytes
        @param: alloc_type : int : The type of memory allocation (most often MEM_COMMIT)
        @param: protection : int : Memory protection to apply to the specified region

        @return: int : Base addr of the allocated region of pages.
        @raise pdx: An exception is raised on failure.
        """

        if addr:
            self._log("VirtualAllocEx(%08X , %d, %08X , %08X )" % (addr, size, alloc_type, protection))
        else:
            self._log("VirtualAllocEx(NULL, %d, %08X , %08X )" % (size, alloc_type, protection))

        allocated_address = kernel32.VirtualAllocEx(self.h_process, addr, size, alloc_type, protection)

        if not allocated_address:
            raise pdx("VirtualAllocEx(%08X , %d, %08X , %08X )" % (addr, size, alloc_type, protection), True)

        return allocated_address

    def virtual_free(self, addr, size, free_type):
        """
        Convenience wrapper around VirtualFreeEx()

        @param: addr   : int : Pointer to the starting addr of the region of memory to be freed
        @param: size      : int : Size of memory region to free, in bytes
        @param: free_type : int : The type of free operation

        @raise pdx: An exception is raised on failure.
        """

        self._log("VirtualFreeEx(%08X , %d, %08X )" % (addr, size, free_type))

        if not kernel32.VirtualFreeEx(self.h_process, addr, size, free_type):
            raise pdx("VirtualFreeEx(%08X , %d, %08X )" % (addr, size, free_type), True)

    def virtual_protect(self, base_address, size, protection):
        """
        Convenience wrapper around VirtualProtectEx()

        @param: base_address : int : Base addr of region of pages whose access protection attributes are to be changed
        @param: size         : int : Size of the region whose access protection attributes are to be changed
        @param: protection   : int : Memory protection to apply to the specified region

        @return: int : Previous access protection.
        @raise pdx: An exception is raised on failure.
        """

        # self._log("VirtualProtectEx( , %08X , %d, %08X , ,)" % (base_address, size, protection))

        old_protect = c_ulong(0)

        if not kernel32.VirtualProtectEx(self.h_process, base_address, size, protection, byref(old_protect)):
            raise pdx("VirtualProtectEx(%08X , %d, %08X )" % (base_address, size, protection), True)

        return old_protect.value

    def virtual_query(self, addr):
        """
        Convenience wrapper around VirtualQueryEx().

        @param: addr : int : Address to query

        @return: MEMORY_BASIC_INFORMATION
        @raise pdx: An exception is raised on failure.
        """

        mbi = MEMORY_BASIC_INFORMATION()

        if kernel32.VirtualQueryEx(self.h_process, addr, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            # raise pdx("VirtualQueryEx(%08X )" % addr, True)
            pass

        if mbi.BaseAddress:
            return mbi
        else:
            return None

    # ---------------------------------------------------------------------------
    # msr
    def read_msr(self, addr):
        """
        Read data from the specified MSR addr.
        through: ntdll.NtSystemDebugControl

        @param: addr : int : MSR addr to read from.

        @return: tuple : (read status, msr structure)
        """

        msr = SYSDBG_MSR()
        msr.Address = 0x1D9
        msr.Data = 0xFF  # must initialize this value.

        status = ntdll.NtSystemDebugControl(SysDbgReadMsr,
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            0)

        return (status, msr)

    def write_msr(self, addr, data):
        """
        Write data to the specified MSR addr.

        @param: addr : int : MSR addr to write to.
        @param: data    : int : Data to write to MSR addr.

        @return: tuple : (read status, msr structure)
        """

        msr = SYSDBG_MSR()
        msr.Address = addr
        msr.Data = data

        status = ntdll.NtSystemDebugControl(SysDbgWriteMsr,
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            0,
                                            0,
                                            0)

        return status

    # ---------------------------------------------------------------------------
    # print
    def dbg_print_all_debug_registers(self):
        """
        *** DEBUG ROUTINE ***

        This is a debugging routine that was used when debugging hardware breakpoints.
        It was too useful to be removed from the release code.
        """

        # ensure we have an up to date context for the current thread.
        context = self.get_thread_context(self.h_thread)

        print("eip = %08X " % context.Eip)
        print("Dr0 = %08X " % context.Dr0)
        print("Dr1 = %08X " % context.Dr1)
        print("Dr2 = %08X " % context.Dr2)
        print("Dr3 = %08X " % context.Dr3)
        print("Dr7 = %s" % self.to_binary(context.Dr7))
        print("      10987654321098765432109876543210")
        print("      332222222222111111111")

    def dbg_print_all_guarded_pages(self):
        """
        *** DEBUG ROUTINE ***

        This is a debugging routine that was used when debugging memory breakpoints.
        It was too useful to be removed from the release code.
        """

        cursor = 0

        # scan through the entire memory range.
        while cursor < 0xFFFFFFFF:
            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            if mbi.Protect & PAGE_GUARD:
                addr = mbi.BaseAddress
                print("PAGE GUARD on %08X " % mbi.BaseAddress)

                while 1:
                    addr += self.page_size
                    tmp_mbi = self.virtual_query(addr)

                    if not tmp_mbi.Protect & PAGE_GUARD:
                        break

                    print("PAGE GUARD on %08X " % addr)

            cursor += mbi.RegionSize

    # ---------------------------------------------------------------------------
    # context
    def get_thread_context(self, thread_handle=None, thread_id=0):
        """
        Convenience wrapper around GetThreadContext().
        Can obtain a thread context via a handle or thread id.

        @param: thread_handle : HANDLE : (Optional) Handle of thread to get context of
        @param: thread_id     : int    : (Optional) ID of thread to get context of

        @return: CONTEXT : Thread CONTEXT on success.

        @raise pdx: An exception is raised on failure.
        """
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # if a thread handle was not specified, get one from the thread id.
        if not thread_handle:
            h_thread = self.open_thread(thread_id)
        else:
            h_thread = thread_handle

        if not kernel32.GetThreadContext(h_thread, byref(context)):
            raise pdx("GetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle:
            self.close_handle(h_thread)

        return context

    def set_thread_context(self, context, thread_handle=None, thread_id=0):
        """
        Convenience wrapper around SetThreadContext().
        Can set a thread context via a handle or thread id.

        @param: thread_handle : HANDLE  : (Optional) Handle of thread to get context of
        @param: context       : CONTEXT : Context to apply to specified thread
        @param: thread_id     : int     : (Optional, Def=0) ID of thread to get context of

        @return: self :

        @raise pdx: An exception is raised on failure.
        """

        # if neither a thread handle or thread id were specified, default to the internal one.
        if not thread_handle and not thread_id:
            h_thread = self.h_thread

        # if a thread handle was not specified, get one from the thread id.
        elif not thread_handle:
            h_thread = self.open_thread(thread_id)

        # use the specified thread handle.
        else:
            h_thread = thread_handle

        if not kernel32.SetThreadContext(h_thread, byref(context)):
            raise pdx("SetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle and thread_id:
            self.close_handle(h_thread)

        return self.ret_self()

    def dump_context_str(self, context=None, stack_depth=5, print_dots=True):
        """
        Return an informational block of text describing the CPU context of the current thread.
        Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @param: context     : Context : (Optional) Current thread context to examine
        @param: stack_depth : int     : (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @param: print_dots  : bool    : (Optional, def:True) Controls suppression of dot in place of non-printable

        @return: string : Information about current thread context.
        """

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = self.dump_context_list(context, stack_depth, print_dots)

        context_dump = "CONTEXT DUMP\n"
        context_dump += "  EIP: %08X  %s\n" % (context.Eip, context_list["eip"])
        context_dump += "  EAX: %08X  (%10d) -> %s\n" % (context.Eax, context.Eax, context_list["eax"])
        context_dump += "  EBX: %08X  (%10d) -> %s\n" % (context.Ebx, context.Ebx, context_list["ebx"])
        context_dump += "  ECX: %08X  (%10d) -> %s\n" % (context.Ecx, context.Ecx, context_list["ecx"])
        context_dump += "  EDX: %08X  (%10d) -> %s\n" % (context.Edx, context.Edx, context_list["edx"])
        context_dump += "  EDI: %08X  (%10d) -> %s\n" % (context.Edi, context.Edi, context_list["edi"])
        context_dump += "  ESI: %08X  (%10d) -> %s\n" % (context.Esi, context.Esi, context_list["esi"])
        context_dump += "  EBP: %08X  (%10d) -> %s\n" % (context.Ebp, context.Ebp, context_list["ebp"])
        context_dump += "  ESP: %08X  (%10d) -> %s\n" % (context.Esp, context.Esp, context_list["esp"])

        for offset in xrange(0, stack_depth + 1):
            context_dump += "  +%02x: %08X  (%10d) -> %s\n" %    \
                (
                    offset * 4,
                    context_list["esp+%02x" % (offset * 4)]["value"],
                    context_list["esp+%02x" % (offset * 4)]["value"],
                    context_list["esp+%02x" % (offset * 4)]["desc"]
                )

        return context_dump

    def dump_context_list(self, context=None, stack_depth=5, print_dots=True, hex_dump=False):
        """
        Return an informational list of items describing the CPU context of the current thread.
        Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @param: context     : Context : (Optional) Current thread context to examine
        @param: stack_depth : int     : (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @param: print_dots  : bool    : (Optional, def:True) Controls suppression of dot in place of non-printable
        @param: hex_dump    : bool    : (Optional, def=False) Return a hex dump in the absense of string detection

        @return: dict : Dictionary of information about current thread context.
        """

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = {}

        context_list["eip"] = self.disasm(context.Eip)
        context_list["eax"] = self.smart_dereference(context.Eax, print_dots, hex_dump)
        context_list["ebx"] = self.smart_dereference(context.Ebx, print_dots, hex_dump)
        context_list["ecx"] = self.smart_dereference(context.Ecx, print_dots, hex_dump)
        context_list["edx"] = self.smart_dereference(context.Edx, print_dots, hex_dump)
        context_list["edi"] = self.smart_dereference(context.Edi, print_dots, hex_dump)
        context_list["esi"] = self.smart_dereference(context.Esi, print_dots, hex_dump)
        context_list["ebp"] = self.smart_dereference(context.Ebp, print_dots, hex_dump)
        context_list["esp"] = self.smart_dereference(context.Esp, print_dots, hex_dump)

        for offset in xrange(0, stack_depth + 1):
            try:
                esp = self.flip_endian_dword(self._read_process_memory(context.Esp + offset * 4, 4))

                context_list["esp+%02x" % (offset * 4)] = {}
                context_list["esp+%02x" % (offset * 4)]["value"] = esp
                context_list["esp+%02x" % (offset * 4)]["desc"] = self.smart_dereference(esp, print_dots, hex_dump)
            except:
                context_list["esp+%02x" % (offset * 4)] = {}
                context_list["esp+%02x" % (offset * 4)]["value"] = 0
                context_list["esp+%02x" % (offset * 4)]["desc"] = "[INVALID]"

        return context_list

    # ---------------------------------------------------------------------------
    # register
    def get_register(self, register):
        """
        Get the value of a register in the debuggee within the context of the self.h_thread.

        @param: register : string : One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP

        @return: int : Value of specified register.
        @raise pdx: An exception is raised on failure.
        """

        self._log("getting %s in thread id %d" % (register, self.dbg_evt.dwThreadId))

        register = register.upper()
        if register not in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"):
            raise pdx("invalid register specified")

        # ensure we have an up to date thread context.
        context = self.get_thread_context(self.h_thread)

        if register == "EAX":
            return context.Eax
        elif register == "EBX":
            return context.Ebx
        elif register == "ECX":
            return context.Ecx
        elif register == "EDX":
            return context.Edx
        elif register == "ESI":
            return context.Esi
        elif register == "EDI":
            return context.Edi
        elif register == "ESP":
            return context.Esp
        elif register == "EBP":
            return context.Ebp
        elif register == "EIP":
            return context.Eip

        # this shouldn't ever really be reached.
        return 0

    def set_register(self, register, value):
        """
        Set the value of a register in the debuggee within the context of the self.h_thread.

        @param: register : string : One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP
        @param: value    : int    : Value to set register to

        @return: self :
        @raise pdx: An exception is raised on failure.
        """

        self._log("setting %s to %08X  in thread id %d" % (register, value, self.dbg_evt.dwThreadId))

        register = register.upper()
        if register not in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"):
            raise pdx("invalid register specified")

        # ensure we have an up to date thread context.
        context = self.get_thread_context(self.h_thread)

        if register == "EAX":
            context.Eax = value
        elif register == "EBX":
            context.Ebx = value
        elif register == "ECX":
            context.Ecx = value
        elif register == "EDX":
            context.Edx = value
        elif register == "ESI":
            context.Esi = value
        elif register == "EDI":
            context.Edi = value
        elif register == "ESP":
            context.Esp = value
        elif register == "EBP":
            context.Ebp = value
        elif register == "EIP":
            context.Eip = value

        self.set_thread_context(context)

        return self.ret_self()

    # ---------------------------------------------------------------------------
    # call stack

    def get_hex_context(self, addr):
        assert self.is_address_valid(addr)
        for len_ in reversed(range(12)):
            if self.is_address_valid(addr + len_):
                return self._read_process_memory(addr, len_)
        assert False

    def convert_addr_to_stack_frame_side(self, addr):
        """将地址转化为栈帧的1边"""
        if addr != 0 and self.is_address_valid(addr):
            md = self.addr_to_module(addr)
            if md is not None:
                # 咱没本事, 不解析符号, 让 core 自己搞去吧
                return StackFrameSideMdNoSym(addr, self.get_hex_context(addr), md.szModule.lower(), md.modBaseAddr)

            else:
                return StackFrameSideHeap(addr, self.get_hex_context(addr), self.get_page_base_by_addr(addr))
        else:
            return StackFrameSideInvalid(addr)

    def convert_fromto_to_stack_frame_raw(self, from_addr, to_addr):
        """
            将栈帧的 from/to 地址转换为 StackFrameRaw() 对象

            @return: obj : StackFrameRaw() 对象
        """
        return StackFrameRaw(self.convert_addr_to_stack_frame_side(from_addr), self.convert_addr_to_stack_frame_side(to_addr))

    def get_call_stack_by_thread(self, h_thread, ctx_thread, max_depth=None, is_fix_api_start=False):
        """
            @param: h_thread         : int    : 线程句柄
            @param: ctx_thread       : struct : Win32 结构, 线程环境
            @param: max_depth        : int    : (optional, dft=None)堆栈的最大深度
            @param: is_fix_api_start : bool   : (optional, dft=False)是否修复 api 调用的栈帧

            @return: obj : CallStackRaw() 对象
        """
        # 初始化结构
        ctx_thread_copy = copy.copy(ctx_thread)
        frame = STACKFRAME64()
        frame.AddrPC = ADDRESS64(ctx_thread_copy.Eip)
        frame.AddrFrame = ADDRESS64(ctx_thread_copy.Ebp)
        frame.AddrStack = ADDRESS64(ctx_thread_copy.Esp)

        # winappdbg.thread.py 没有这个
        frame.AddrPC.Mode = 3
        frame.AddrFrame.Mode = 3
        frame.AddrStack.Mode = 3

        # 如果修复 api 调用堆栈, 则保存当前 esp 上的地址为修复后的 to 地址
        if is_fix_api_start:
            fix_to_addr = read_stack_int32(self, 0)

        # 遍历
        call_stack_raw = CallStackRaw()
        while windll.dbghelp.StackWalk64(IMAGE_FILE_MACHINE_I386, self.h_process, h_thread, byref(frame), None, None, None, None, None):

            if frame.AddrPC.Offset != 0:

                # addr : frame.AddrFrame.Offset + 4 (stack addr)
                # from : frame.AddrPC.Offset (function start addr)
                # to   : frame.AddrReturn.Offset (return to addr)

                # todo: fix_to_addr shall be valid addr
                if is_fix_api_start and len(call_stack_raw) == 0 and fix_to_addr > 0x1000:

                    # 最底层的 api 调用. 将此帧分割为2个帧
                    call_stack_raw.append_frame(self.convert_fromto_to_stack_frame_raw(frame.AddrPC.Offset, fix_to_addr))
                    call_stack_raw.append_frame(self.convert_fromto_to_stack_frame_raw(fix_to_addr, frame.AddrReturn.Offset))

                else:
                    # 非最底层 api 调用, 直接添加即可
                    call_stack_raw.append_frame(self.convert_fromto_to_stack_frame_raw(frame.AddrPC.Offset, frame.AddrReturn.Offset))
            else:
                # 遍历结束
                break

            # 已到达最大深度. 设置 meta 然后退出循环
            if max_depth is not None and len(call_stack_raw) >= max_depth or len(call_stack_raw) > self.call_stack_depth_max:
                call_stack_raw.add_meta("reach max depth")
                break

        return call_stack_raw

    def get_call_stack_raw(self, max_depth=None, is_fix_api_start=False):
        """
            @return: obj : CallStackRaw() 对象
        """
        return self.get_call_stack_by_thread(h_thread=self.h_thread, ctx_thread=self.context, max_depth=max_depth, is_fix_api_start=is_fix_api_start)

    def get_call_stack_frames(self, max_depth=None, is_fix_api_start=False):
        """
            get call stack of self.h_thread

            @param: max_depth            : int or None : (optional, dft=None)stack depth. default None, meaning all stacks.
            @Param: is_fix_api_start : bool        : shall we fix call stack when pause at api start address.
                                                     for unknown reason, when we pause at api start address, the first frame is incorrent.
                                                     we need to fix it manually.

            @return: list : a list of _share_this.StackFrame() obj. list maybe empty.

            ref:
                x64dbg\src\dbg\stackinfo.cpp
                winappdbg\thread.py
        """
        return self.get_call_stack_by_thread(h_thread=self.h_thread, ctx_thread=self.context, max_depth=max_depth, is_fix_api_start=is_fix_api_start)

    def get_call_stacks_all(self, max_depth=None, is_fix_api_start=False):
        """
            get call stack of all threads.

            @param: depth            :
            @param: is_fix_api_start :

            @return: dict : like this: {tid1: call_stack_list1,
                                        tid2: call_stack_list2,
                                        ...}

            !+ currently used when process exit
        """
        # todo: if process exit, this cause exception
        # self.suspend_all_threads()

        ret = {}
        for tid in self.enumerate_threads():

            h_thread = self.open_thread(tid)
            ctx_thread = self.get_thread_context(thread_handle=h_thread)
            ret[tid] = self.get_call_stack_by_thread(h_thread=h_thread, ctx_thread=ctx_thread, max_depth=max_depth, is_fix_api_start=is_fix_api_start)
            self.close_handle(h_thread)

        # self.resume_all_threads()

        return ret

    # ---------------------------------------------------------------------------
    # END OF CLASS
    # ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
