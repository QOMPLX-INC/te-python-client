#
# etf.py - Erlang External Term Format: adapted from https://github.com/samuel/python-erlastic
# Copyright 2015-2021 -- QOMPLX, Inc. -- All Rights Reserved.  No License Granted.
#

#############################################################################

import sys, zlib, struct

FORMAT_VERSION = 131

NEW_FLOAT_EXT = 70      # [Float64:IEEE float]
BIT_BINARY_EXT = 77     # [UInt32:Len, UInt8:Bits, Len:Data]
SMALL_INTEGER_EXT = 97  # [UInt8:Int]
INTEGER_EXT = 98        # [Int32:Int]
FLOAT_EXT = 99          # [31:Float String] Float in string format (formatted "%.20e", sscanf "%lf"). Superseded by NEW_FLOAT_EXT
ATOM_EXT = 100          # 100 [UInt16:Len, Len:AtomName] max Len is 255
REFERENCE_EXT = 101     # 101 [atom:Node, UInt32:ID, UInt8:Creation]
PORT_EXT = 102          # [atom:Node, UInt32:ID, UInt8:Creation]
PID_EXT = 103           # [atom:Node, UInt32:ID, UInt32:Serial, UInt8:Creation]
SMALL_TUPLE_EXT = 104   # [UInt8:Arity, N:Elements]
LARGE_TUPLE_EXT = 105   # [UInt32:Arity, N:Elements]
NIL_EXT = 106           # empty list
STRING_EXT = 107        # [UInt32:Len, Len:Characters]
LIST_EXT = 108          # [UInt32:Len, Elements, Tail]
BINARY_EXT = 109        # [UInt32:Len, Len:Data]
SMALL_BIG_EXT = 110     # [UInt8:n, UInt8:Sign, n:nums]
LARGE_BIG_EXT = 111     # [UInt32:n, UInt8:Sign, n:nums]
NEW_FUN_EXT = 112       # [UInt32:Size, UInt8:Arity, 16*Uint6-MD5:Uniq, UInt32:Index, UInt32:NumFree, atom:Module, int:OldIndex, int:OldUniq, pid:Pid, NunFree*ext:FreeVars]
EXPORT_EXT = 113        # [atom:Module, atom:Function, smallint:Arity]
NEW_REFERENCE_EXT = 114 # [UInt16:Len, atom:Node, UInt8:Creation, Len*UInt32:ID]
SMALL_ATOM_EXT = 115    # [UInt8:Len, Len:AtomName]
FUN_EXT = 117           # [UInt4:NumFree, pid:Pid, atom:Module, int:Index, int:Uniq, NumFree*ext:FreeVars]
COMPRESSED = 80         # [UInt4:UncompressedSize, N:ZlibCompressedData]

const_false = b"false" if sys.version_info >= (3,5,0) else "false"
const_true = b"true" if sys.version_info >= (3,5,0) else "true"
const_none = b"none" if sys.version_info >= (3,5,0) else "none"

def term_to_binary(obj, compressed=False):
    ubuf = term_to_binary_part(obj)
    if compressed is True:
        compressed = 6
    if not (compressed is False or (isinstance(compressed, int) and compressed >= 0 and compressed <= 9)):
        raise TypeError("compressed must be True, False or an integer between 0 and 9")
    if compressed:
        cbuf = zlib.compress(ubuf, compressed)
        if len(cbuf) < len(ubuf):
            usize = struct.pack(">L", len(ubuf))
            return to_chr(FORMAT_VERSION) + to_chr(COMPRESSED) + usize + cbuf
    return to_chr(FORMAT_VERSION) + ubuf

def term_to_binary_part(obj):
    if obj is False:
       return to_chr(ATOM_EXT) + struct.pack(">H", 5) + const_false
    elif obj is True:
        return to_chr(ATOM_EXT) + struct.pack(">H", 4) + const_true
    elif obj is None:
        return to_chr(ATOM_EXT) + struct.pack(">H", 4) + const_none
    elif isinstance(obj, int):
        if 0 <= obj <= 255:
            return to_chr(SMALL_INTEGER_EXT) + to_chr(obj)
        elif -2147483648 <= obj <= 2147483647:
            return to_chr(INTEGER_EXT) + struct.pack(">l", obj)
        else:
            sign = obj < 0
            obj = abs(obj)

            big_buf = b"" if sys.version_info >= (3,5,0) else ""
            while obj > 0:
                big_buf += to_chr(obj & 0xff)
                obj >>= 8

            if len(big_buf) < 256:
                return to_chr(SMALL_BIG_EXT) + to_chr(len(big_buf)) + to_chr(sign) + big_buf
            else:
                return to_chr(LARGE_BIG_EXT) + struct.pack(">L", len(big_buf)) + to_chr(sign) + big_buf
    elif isinstance(obj, float):
        floatstr = ("%.20e" % obj).encode('ascii')
        endcode = b"\x00" if sys.version_info >= (3,5,0) else "\x00"
        return to_chr(FLOAT_EXT) + floatstr + endcode * (31 - len(floatstr))
    elif is_string(obj):
        st = obj.encode('utf-8')
        return to_chr(BINARY_EXT) + struct.pack(">L", len(st)) + st
    elif isinstance(obj, bytes):
        return to_chr(BINARY_EXT) + struct.pack(">L", len(obj)) + obj
    elif isinstance(obj, tuple):
        n = len(obj)
        if n < 256:
            buf = to_chr(SMALL_TUPLE_EXT) + to_chr(n)
        else:
            buf = to_chr(LARGE_TUPLE_EXT) + struct.pack(">L", n)
        for item in obj:
            buf += term_to_binary_part(item)
        return buf
    elif obj == []:
        return to_chr(NIL_EXT)
    elif isinstance(obj, list):
        buf = to_chr(LIST_EXT) + struct.pack(">L", len(obj))
        for item in obj:
            buf += term_to_binary_part(item)
        buf += to_chr(NIL_EXT)
        return buf
    elif isinstance(obj, dict):
        buf = to_chr(LIST_EXT) + struct.pack(">L", len(obj))
        for item in obj.items():
            buf += term_to_binary_part(item)
        buf += to_chr(NIL_EXT)
        return buf
    else:
        raise ValueError("Unexpected term to serialize %r" % obj)

#############################################################################

def is_string(obj):
    if sys.version_info >= (3,5,0):
        return isinstance(obj, str)
    else:
        return isinstance(obj, str) or isinstance(obj, unicode)

def to_chr(val):
    return bytes([val]) if sys.version_info >= (3,5,0) else chr(val)

#############################################################################
