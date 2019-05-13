# -*- coding: utf-8 -*-

"""

"""

from __future__ import print_function
# # from __future__ import unicode_literals


import pefile
import chardet

# ---------------------------------------------------------------------------


def time_str():
    """
        time string in this format: xx

        @return: STRING :
    """
    return time.strftime('%Y%m%d_%H_%M_%S', time.localtime(time.time()))


def rand_str():
    """
        random string in this format: xx

        @return: STRING :
    """
    return "%d_%d_%d" % (random.randint(10, 99), random.randint(10, 99), random.randint(10, 99))


def to_unicode(unicode_or_str):
    """转化为 Python2 的 unicode"""
    if isinstance(unicode_or_str, str):
        value = unicode_or_str.decode('utf-8')
    else:
        value = unicode_or_str
    return value


def to_str(unicode_or_str):
    """转化为 Python2 的 str"""
    if isinstance(unicode_or_str, unicode):
        value = unicode_or_str.encode('utf-8')
    else:
        value = unicode_or_str
    return value


# def to_str(bytes_or_str):
#     """转化为 Python3 的 str"""
#     if isinstance(bytes_or_str, bytes):
#         value = bytes_or_str.decode('utf-8')
#     else:
#         value = bytes_or_str
#     return value
#
#
# def to_bytes(bytes_or_str):
#     """转化为 Python3 的 byte"""
#     if isinstance(bytes_or_str, str):
#         value = bytes_or_str.encode('utf-8')
#     else:
#         value = bytes_or_str
#     return value


# ---------------------------------------------------------------------------
class XPE(pefile.PE):
    # ---------------------------------------------------------------------------
    # wrapper of pefile.PE
    # ---------------------------------------------------------------------------

    def __init__(self, name):
        """
            @param: name : STRING : pe full path
        """
        pefile.PE.__init__(self, name)

    def get_export_table(self):
        """
            get parsed export table

            @return: obj : obj of ExportDirData
                     None
        """
        return hasattr(self, "DIRECTORY_ENTRY_EXPORT") and self.DIRECTORY_ENTRY_EXPORT or None

    def get_export_dict(self):
        """
            get parsed export table as dict

            @return: DICT: {export_name_1: export_addr_1, export_name_2: export_addr_2}
                     None
        """
        try:
            exports = self.get_export_table()
            if exports and len(exports.symbols) != 0:
                ret = {}
                for export_item in exports.symbols:
                    ret[export_item.name] = export_item.address
                return ret
            return None
        except:
            return None

    def get_export_item_rva(self, export_name):
        """
            get export item rva by export name

            @param: INT
                    None
        """
        exports = self.get_export_table()
        if exports:
            for export_item in exports.symbols:
                if export_item.name == export_name:
                    return export_item.address
        return None

    def get_ep_offset(self):
        return self.OPTIONAL_HEADER.AddressOfEntryPoint


# ---------------------------------------------------------------------------

import struct
from ctypes import *


# ---------------------------------------------------------------------------
# borrowed
def check_bits_consistancy(bits):
    assert not bits % 8, "bits should be sizeof(char) aligned, got %d" % bits


def dInt(sint):
    """
    Turns sint into an int, hopefully
    python's int() doesn't handle negatives with base 0 well
    """
    if sint is None or type(sint) in [type((1, 1)), type([1]), type({})]:
        # devlog("Type ERROR: dInt(%s)!"%str(sint))
        # should we call bugcheck here?
        # raise TypeError, "type %s for dInt(%s)" % (type(sint), str(sint))
        raise TypeError("type %s for dInt(%s)" % (type(sint), str(sint)))

    s = str(sint)
    if s[0:2] == "0x":
        return long(s, 0)
    else:
        # if you have long("5.0") it throws a horrible exception
        # so we convert to float and then back to long to avoid this
        return long(float(s))


def uint_bits(bits, c):
    # WARNING i dunno if dInt is safe here
    c = dInt(c)
    # [Python < 2.4] FutureWarning: x<<y losing bits or changing sign will return a long in Python 2.4 and up
    # [Python < 2.4] 1 << 32 = 0
    # so we force python < 2.4 to use a long.
    return c & ((long(1) << bits) - 1)


def split_int_bits(bits, i):
    check_bits_consistancy(bits)
    # we cast to uint_bits here to be sure to return (bits/8) x uint8
    u = uint_bits(bits, i)
    r = []
    for b in range(0, bits, 8):
        r += [(u >> (bits - (b + 8))) & 0xff]
    return r


def int2list_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    l = split_int_bits(bits, i)
    # devlog("int2list: l = %s" % l)
    lc = []
    for n in l:
        # devlog("int2list: n = 0x%x" % n)
        lc += [chr(n)]
    if swap:
        lc.reverse()
    return lc


def int2str_bits(bits, i, swap=0):
    check_bits_consistancy(bits)
    return "".join(int2list_bits(bits, i, swap=swap))


def int2str8(int8, swap=0):
    return int2str_bits(8, int8, swap=swap)


def int2str8_swap(int8):
    return int2str_bits(8, int8, swap=1)


def int2str16(int16, swap=0):
    return int2str_bits(16, int16, swap=swap)


def int2str16_swapped(int16):
    return int2str_bits(16, int16, swap=1)


def int2str32(int32, swap=0):
    return int2str_bits(32, int32, swap=swap)


def int2str32_swapped(int32):
    return int2str_bits(32, int32, swap=1)


def read_int8(reader, address):
    buf = reader.read(address, 1)

    if len(buf) != 1:
        # todo: we shall fix this
        _error("read int8 from addr %.8X, but got but len: %d" % (address, len(buf)))
        return 0

    return ord(buf)


def read_int16(reader, address):
    buf = reader.read(address, 2)

    if len(buf) != 2:
        # todo: we shall fix this
        _error("read int16 from addr %.8X, but got but len: %d" % (address, len(buf)))
        return 0

    v = struct.unpack('<h', buf)[0]
    return c_uint16(v).value


def read_int32(reader, address):
    buf = reader.read(address, 4)

    if len(buf) != 4:
        # todo: we shall fix this
        _error("read int32 from addr %.8X, but got but len: %d" % (address, len(buf)))
        return 0

    v = struct.unpack('<L', buf)[0]
    return c_uint32(v).value


def read_stack_int8(reader, offset):
    return read_int8(reader, reader.get_esp() + offset)


def read_stack_int16(reader, offset):
    return read_int16(reader, reader.get_esp() + offset)


def read_stack_int32(reader, offset):
    return read_int32(reader, reader.get_esp() + offset)


def read_stack_p_int8(reader, offset):
    address = read_int32(reader, reader.get_esp() + offset)
    return read_int8(reader, address)


def read_stack_p_int16(reader, offset):
    address = read_int32(reader, reader.get_esp() + offset)
    return read_int16(reader, address)


def read_stack_p_int32(reader, offset):
    address = read_int32(reader, reader.get_esp() + offset)
    return read_int32(reader, address)

# ---------------------------------------------------------------------------


def retrive_ascii_string(data):
    """
    Retrieve the ASCII string, if any, from data.
    Ensure that the string is valid by checking against the minimum length requirement defined in STRING_EXPLORATION_MIN_LENGTH.

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

    STRING_EXPLORATION_MIN_LENGTH = 2
    if len(discovered) < STRING_EXPLORATION_MIN_LENGTH:
        return False

    return discovered


def data_to_unicode_str_ori(data, max_len):
    """
        @param: data    : raw :
        @param: max_len : int :

        @return: string :
    """
    discovered = ""
    every_other = True
    for char in data:
        if every_other:
            # if we've hit a non printable char, break
            if ord(char) < 32 or ord(char) > 126:
                break
            discovered += char
        every_other = not every_other

    if len(discovered) < max_len:
        return ""

    return discovered


def retrive_unicode_data(data, max_len):
    """
        @param: data    : raw :
        @param: max_len : int :

        @return: tuple : (string, int)
    """
    data_x = ""
    i = 0
    while i < len(data) and i < max_len:
        s = data[i:i + 2]
        if s[0] == "\x00" and s[1] == "\x00":
            break
        data_x = data_x + s
        i = i + 2
    return data_x, i


def data_to_unicode_str_encoding_ascii(data, max_len):
    """
        @param: data    : raw :
        @param: max_len : int :

        @return: string :
    """
    i = 0
    ret = ""
    while i < len(data) - 1 and i < max_len:
        s = data[i:i + 2]
        i = i + 2
        ret = ret + unicode(s).strip("\0")
    return ret


def data_to_unicode_str_my(data, max_len):
    """
        try to resolve unicode string from data

        @param: data    : raw :
        @param: max_len : int :

        @return: string :
    """
    encoding = chardet.detect(data)["encoding"]

    if encoding == "GB2312":
        return data.decode("GB2312")

    elif encoding == "ascii":
        return data_to_unicode_str_encoding_ascii(data, max_len)

    elif encoding == "windows-1252":
        return data.decode("windows-1252")

    elif encoding == "utf-8":
        return data.decode("utf-8")

    else:
        if encoding is not None:
            print("." * 100)
            print("invalid decode: %s" % chardet.detect(data))
            print("." * 100)

        # try multiple encodings
        try:
            return data_to_unicode_str_encoding_ascii(data, max_len)
        except:
            try:
                return data.decode("GB2312")
            except:
                return ""


def data_to_unicode_str(data, max_len):
    """
        todo: for invalid chars, we get "" here

        @param: data    : raw :
        @param: max_len : int :

        @return: unicode : unicode, not string
    """
    data, max_len = retrive_unicode_data(data, max_len)

    ret = data_to_unicode_str_my(data, max_len)
    if len(ret) == 0:
        ret = data_to_unicode_str_ori(data, max_len)

    return ret


def retrive_unicode_string(data, max_len=1024):
    """
    description

    @param: data : raw : Data to explore for printable unicode string

    @return: string : string, not unicode string
           : False  : failure
    """
    ret = data_to_unicode_str(data, max_len)
    if len(ret) < 2:
        return False

    try:
        return str(ret)
    except:
        _error("convert unicode to string fail...")
        return False

    # ret = ""
    # try:
    #     i = 0
    #     while i < len(data) and i < self.STRING_EXPLORATION_MIN_LENGTH:
    #         s = data[i:i + 2]
    #         ret = ret + unicode(s).strip("\0")
    #         i = i + 2
    # except:
    #     pass
    # return ret

    # discovered = ""
    # every_other = True
    # for char in data:
    #     if every_other:
    #         # if we've hit a non printable char, break
    #         if ord(char) < 32 or ord(char) > 126:
    #             break
    #         discovered += char
    #     every_other = not every_other
    # if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
    #     return False
    # return discovered


def read_ascii_string(reader, address, max_bytes=1024):
    """
    read ascii string from debugee at sepcified address

    @param: address   : int : read address
    @param: max_bytes : int : max read string len

    @return: string :
           : None   :
    """
    buf = reader.read(address, 1)
    if buf and len(buf) == 1 and buf[0] != '\00':

        # this is too ugly
        # if required bytes is too "large", this "read" action might return None, so we need to minimize size required, and read many times
        ret = retrive_ascii_string(reader.read(address, max_bytes))
        if not ret and max_bytes >= 1024:

            ret = retrive_ascii_string(reader.read(address, 256))
            if not ret:
                ret = retrive_ascii_string(reader.read(address, 48))

        return ret and ret or None

    return None


def read_printable_string(reader, address, max_bytes=1024):
    """
        read printable string from debugee at sepcified address

        @param: address   : int : read address
        @param: max_bytes : int : max read string len

        @return: string :
               : None   :
    """
    buf = reader.read(address, 1)
    if buf and len(buf) == 1 and reader.is_char_printable(buf[0]):

        # this is too ugly
        # if required bytes is too "large", this "read" action might return None, so we need to minimize size required, and read many times
        ret = retrive_printable_string(reader.read(address, max_bytes))
        if not ret and max_bytes >= 1024:

            ret = retrive_printable_string(reader.read(address, 256))
            if not ret:
                ret = retrive_printable_string(reader.read(address, 48))

        return ret and ret or None

    return None


def read_unicode_string(reader, address, max_bytes=1024):
    """
        read unicode string from debugee at sepcified address

        @param: address   : int : read address
        @param: max_bytes : int : max read string len(bytes)

        @return: string : !+ string, not unicode string
               : None   :
    """
    buf = reader.read(address, 2)
    if buf and len(buf) == 2 and (buf[0] != '\00' or buf[1] != '\00'):

        # this is too ugly
        # if required bytes is too "large", this "read" action might return None, so we need to minimize size required, and read many times
        ret = retrive_unicode_string(reader.read(address, max_bytes))
        if not ret and max_bytes >= 1024:

            ret = retrive_unicode_string(reader.read(address, 256))
            if not ret:
                ret = retrive_unicode_string(reader.read(address, 48))

        return ret and ret or None

    return None


def read_p_ascii_string(reader, address, max_bytes=1024):
    """
        @param: address   : int : address to read
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, address)
    return read_ascii_string(reader, address, max_bytes)


def read_p_printable_string(reader, address, max_bytes=1024):
    """
        @param: address   : int : address to read
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, address)
    return read_printable_string(reader, address, max_bytes)


def read_p_unicode_string(reader, address, max_bytes=1024):
    """
        @param: address   : int : address to read
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string : !+ string, not unicode string
               : None   :
    """
    address = read_int32(reader, address)
    return read_unicode_string(reader, address, max_bytes)


def read_pp_ascii_string(reader, address, max_bytes=1024):
    """
        @param: address   : int : address to read
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, address)
    address = read_int32(reader, address)
    return read_ascii_string(reader, address, max_bytes)


def read_pp_printable_string(reader, address, max_bytes=1024):
    """
        @param: address   : int : address to read
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, address)
    address = read_int32(reader, address)
    return read_printable_string(reader, address, max_bytes)


def read_pp_unicode_string(reader, address, max_bytes=1024):
    """
        @param: address   : int : address to read
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string : !+ string, not unicode string
               : None   :
    """
    address = read_int32(reader, address)
    address = read_int32(reader, address)
    return read_unicode_string(reader, address, max_bytes)


def read_stack_ascii_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    return read_ascii_string(reader, reader.get_esp() + offset, max_bytes)


def read_stack_printable_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    return read_printable_string(reader, reader.get_esp() + offset, max_bytes)


def read_stack_unicode_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string : !+ string, not unicode string
               : None   :
    """
    return read_unicode_string(reader, reader.get_esp() + offset, max_bytes)


def read_stack_p_ascii_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, reader.get_esp() + offset)
    return read_ascii_string(reader, address, max_bytes)


def read_stack_p_printable_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, reader.get_esp() + offset)
    return read_printable_string(reader, address, max_bytes)


def read_stack_p_unicode_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string : !+ string, not unicode string
               : None   :
    """
    address = read_int32(reader, reader.get_esp() + offset)
    return read_unicode_string(reader, address, max_bytes)


def read_stack_pp_ascii_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, reader.get_esp() + offset)
    address = read_int32(reader, address)
    return read_ascii_string(reader, address, max_bytes)


def read_stack_pp_printable_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string :
               : None   :
    """
    address = read_int32(reader, reader.get_esp() + offset)
    address = read_int32(reader, address)
    return read_printable_string(reader, address, max_bytes)


def read_stack_pp_unicode_string(reader, offset, max_bytes=1024):
    """
        @param: offset    : int : stack offset
        @param: max_bytes : int : (optional, dft=1024) max string bytes to read

        @return: string : !+ string, not unicode string
               : None   :
    """
    address = read_int32(reader, reader.get_esp() + offset)
    address = read_int32(reader, address)
    return read_unicode_string(reader, address, max_bytes)

# ---------------------------------------------------------------------------


def write_int8(writer, address, value):
    assert value >= -0xFF
    assert value <= 0xFF
    writer.write(address, int2str8_swap(value), length=1)


def write_int16(writer, address, value):
    assert value >= -0xFFFF
    assert value <= 0xFFFF
    writer.write(address, int2str16_swapped(value), length=2)


def write_int32(writer, address, value):
    assert value >= -0xFFFFFFFF
    assert value <= 0xFFFFFFFF
    writer.write(address, int2str32_swapped(value), length=4)

# ---------------------------------------------------------------------------


def write_ascii_string(writer, address, str_):
    encoding = chardet.detect(str_)['encoding']
    if encoding == "ascii":

        data = str_ + '\00'
        writer.write(address, data)

    else:
        print(">>> not surpoted ascii string....")
        assert False


def write_unicode_string(writer, address, str_):
    encoding = chardet.detect(str_)['encoding']
    if encoding == "ascii":

        data = ""
        for i in range(len(str_)):
            data = data + str_[i] + '\00'
        data = data + '\00\00'

        writer.write(address, data)

    else:
        print(">>> not surpoted unicode string....")
        assert False


def write_stack_int8(writer, offset, value):
    write_int8(writer, writer.get_esp() + offset, value)


def write_stack_int16(writer, offset, value):
    write_int16(writer, writer.get_esp() + offset, value)


def write_stack_int32(writer, offset, value):
    write_int32(writer, writer.get_esp() + offset, value)


def write_stack_ascii_string(writer, offset, str_):
    write_ascii_string(writer, writer.get_esp() + offset, value)


def write_stack_unicode_string(writer, offset, str_):
    write_unicode_string(writer, writer.get_esp() + offset, value)


def write_stack_p_int8(writer, offset, value):
    addr = read_int32(writer, writer.get_esp() + offset)
    write_int8(writer, addr, value)


def write_stack_p_int16(writer, offset, value):
    addr = read_int32(writer, writer.get_esp() + offset)
    write_int16(writer, addr, value)


def write_stack_p_int32(writer, offset, value):
    addr = read_int32(writer, writer.get_esp() + offset)
    write_int32(writer, addr, value)


def write_stack_p_ascii_string(writer, offset, str_):
    addr = read_int32(writer, writer.get_esp() + offset)
    write_ascii_string(writer, addr, str_)


def write_stack_p_unicode_string(writer, offset, str_):
    addr = read_int32(writer, writer.get_esp() + offset)
    write_unicode_string(writer, addr, str_)


def write_stack_pp_int8(writer, offset, value):
    addr = read_int32(writer, writer.get_esp() + offset)
    addr = read_int32(writer, addr)
    write_int8(writer, addr, value)


def write_stack_pp_int16(writer, offset, value):
    addr = read_int32(writer, writer.get_esp() + offset)
    addr = read_int32(writer, addr)
    write_int16(writer, addr, value)


def write_stack_pp_int32(writer, offset, value):
    addr = read_int32(writer, writer.get_esp() + offset)
    addr = read_int32(writer, addr)
    write_int32(writer, addr, value)


def write_stack_pp_ascii_string(writer, offset, str_):
    addr = read_int32(writer, writer.get_esp() + offset)
    addr = read_int32(writer, addr)
    write_ascii_string(writer, addr, str_)


def write_stack_pp_unicode_string(writer, offset, str_):
    addr = read_int32(writer, writer.get_esp() + offset)
    addr = read_int32(writer, addr)
    write_unicode_string(writer, addr, str_)


# ---------------------------------------------------------------------------


def to_hex(buf):
    return ' '.join('%02X' % ord(c) for c in buf)


# ---------------------------------------------------------------------------


if __name__ == "__main__":
    pass


# ---------------------------------------------------------------------------
# END OF FILE
# ---------------------------------------------------------------------------
