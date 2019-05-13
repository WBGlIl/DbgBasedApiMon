
# -*- coding: utf-8 -*-

"""
"""

from __future__ import print_function
# from __future__ import unicode_literals

from my_ctypes import *
from windows_h import *

###
# manually declare entities from Tlhelp32.h since i was unable to import using h2xml.py.
###

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_INHERIT = 0x80000000
TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)


class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          DWORD),
        ('tpDeltaPri',         DWORD),
        ('dwFlags',            DWORD),
    ]


class PROCESSENTRY32(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   DWORD),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      DWORD),
        ('dwFlags',             DWORD),
        ('szExeFile',           CHAR * 260),
    ]


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   DWORD),
        ("modBaseSize",   DWORD),
        ("hModule",       DWORD),
        ("szModule",      CHAR * 256),
        ("szExePath",     CHAR * 260),
    ]


class _MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState",      DWORD),
        ("dwLocalAddr",  DWORD),
        ("dwLocalPort",  DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid",  DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        _MIB_TCPROW_OWNER_PID * 512)
    ]


class _MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD)
    ]


class MIB_UDPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        _MIB_UDPROW_OWNER_PID * 512)
    ]


###
# manually declare various structures as needed.
###

class SYSDBG_MSR(Structure):
    _fields_ = [
        ("Address", c_ulong),
        ("Data",    c_ulonglong),
    ]

###
# manually declare various #define's as needed.
###

# debug event codes.
EXCEPTION_DEBUG_EVENT = 0x00000001
CREATE_THREAD_DEBUG_EVENT = 0x00000002
CREATE_PROCESS_DEBUG_EVENT = 0x00000003
EXIT_THREAD_DEBUG_EVENT = 0x00000004
EXIT_PROCESS_DEBUG_EVENT = 0x00000005
LOAD_DLL_DEBUG_EVENT = 0x00000006
UNLOAD_DLL_DEBUG_EVENT = 0x00000007
OUTPUT_DEBUG_STRING_EVENT = 0x00000008
RIP_EVENT = 0x00000009
USER_CALLBACK_DEBUG_EVENT = 0xDEADBEEF     # added for callback support in debug event loop.

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_SINGLE_STEP = 0x80000004

# hw breakpoint conditions
HW_ACCESS = 0x00000003
HW_EXECUTE = 0x00000000
HW_WRITE = 0x00000001

CONTEXT_CONTROL = 0x00010001
CONTEXT_FULL = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010
CREATE_NEW_CONSOLE = 0x00000010
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
DBG_EXCEPTION_HANDLED = 0x00010001
DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
EFLAGS_RF = 0x00010000
EFLAGS_TRAP = 0x00000100
ERROR_NO_MORE_FILES = 0x00000012
FILE_MAP_READ = 0x00000004
FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
INVALID_HANDLE_VALUE = 0xFFFFFFFF
MEM_COMMIT = 0x00001000
MEM_DECOMMIT = 0x00004000
MEM_IMAGE = 0x01000000
MEM_RELEASE = 0x00008000
PAGE_NOACCESS = 0x00000001
PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400
PROCESS_ALL_ACCESS = 0x001F0FFF
SE_PRIVILEGE_ENABLED = 0x00000002
SW_SHOW = 0x00000005
THREAD_ALL_ACCESS = 0x001F03FF
TOKEN_ADJUST_PRIVILEGES = 0x00000020
UDP_TABLE_OWNER_PID = 0x00000001
VIRTUAL_MEM = 0x00003000

# for NtSystemDebugControl()
SysDbgReadMsr = 16
SysDbgWriteMsr = 17

# for mapping TCP ports and PIDs
AF_INET = 0x00000002
AF_INET6 = 0x00000017
MIB_TCP_STATE_LISTEN = 0x00000002
TCP_TABLE_OWNER_PID_ALL = 0x00000005


BOOL = c_bool
WORD = c_uint16
DWORD = c_uint32
DWORD64 = c_uint64
ADDRESS_MODE = DWORD
PVOID = c_void_p


class ADDRESS64 (Structure):
    _fields_ = [
        ("Offset",      DWORD64),
        ("Segment",     WORD),
        ("Mode",        ADDRESS_MODE),  # it's a member of the ADDRESS_MODE enum.
    ]


class KDHELP64 (Structure):
    _fields_ = [
        ("Thread",              DWORD64),
        ("ThCallbackStack",     DWORD),
        ("ThCallbackBStore",    DWORD),
        ("NextCallback",        DWORD),
        ("FramePointer",        DWORD),
        ("KiCallUserMode",      DWORD64),
        ("KeUserCallbackDispatcher",    DWORD64),
        ("SystemRangeStart",    DWORD64),
        ("KiUserExceptionDispatcher",   DWORD64),
        ("StackBase",           DWORD64),
        ("StackLimit",          DWORD64),
        ("Reserved",            DWORD64 * 5),
    ]


class STACKFRAME64(Structure):
    _fields_ = [
        ("AddrPC",          ADDRESS64),
        ("AddrReturn",      ADDRESS64),
        ("AddrFrame",       ADDRESS64),
        ("AddrStack",       ADDRESS64),
        ("AddrBStore",      ADDRESS64),
        ("FuncTableEntry",  PVOID),
        ("Params",          DWORD64 * 4),
        ("Far",             BOOL),
        ("Virtual",         BOOL),
        ("Reserved",        DWORD64 * 3),
        ("KdHelp",          KDHELP64),
    ]
LPSTACKFRAME64 = POINTER(STACKFRAME64)
IMAGE_FILE_MACHINE_I386 = 0x014c  # Intel x86
LPDWORD     = POINTER(DWORD)


class SYMBOL_INFO(Structure):
    _fields_ = [
        ('SizeOfStruct', c_ulong),
        ('TypeIndex', c_ulong),
        ('Reserved', c_ulonglong * 2),
        ('Index', c_ulong),
        ('Size', c_ulong),
        ('ModBase', c_ulonglong),
        ('Flags', c_ulong),
        ('Value', c_ulonglong),
        ('Address', c_ulonglong),
        ('Register', c_ulong),
        ('Scope', c_ulong),
        ('Tag', c_ulong),
        ('NameLen', c_ulong),
        ('MaxNameLen', c_ulong),
        ('Name', c_char * 2001)]


# typedef struct _FILETIME {
#    DWORD dwLowDateTime;
#    DWORD dwHighDateTime;
# } FILETIME, *PFILETIME;
class FILETIME(Structure):
    _fields_ = [
        ('dwLowDateTime',       DWORD),
        ('dwHighDateTime',      DWORD),
    ]

# typedef struct _SYSTEMTIME {
#   WORD wYear;
#   WORD wMonth;
#   WORD wDayOfWeek;
#   WORD wDay;
#   WORD wHour;
#   WORD wMinute;
#   WORD wSecond;
#   WORD wMilliseconds;
# }SYSTEMTIME, *PSYSTEMTIME;
class SYSTEMTIME(Structure):
    _fields_ = [
        ('wYear',           WORD),
        ('wMonth',          WORD),
        ('wDayOfWeek',      WORD),
        ('wDay',            WORD),
        ('wHour',           WORD),
        ('wMinute',         WORD),
        ('wSecond',         WORD),
        ('wMilliseconds',   WORD),
    ]

"""
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP      // Obsolete....
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b
#define IRP_MJ_SCSI                     IRP_MJ_INTERNAL_DEVICE_CONTROL
"""
