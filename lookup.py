__author__ = 'CwT'

from idaapi import *
from idautils import *
from idc import *
import struct

global baseAddr

def writefile(file, addr, len):
    for i in range(len):
        one = getByte(addr+i)
        file.write(struct.pack("B", one))

def getDword(addr):
    return Dword(addr)

def getByte(addr):
    return Byte(addr)

def getWord(addr):
    return Word(addr)

def dexGetStringData(dexfile, offset):
    addr = dexfile.baseAddr + offset
    while getByte(addr) > 0x7f:     # skip uleb len
        addr += 1
    addr += 1
    str = ""
    one = getByte(addr)
    while one != 0:
        str += chr(one)
        addr += 1
        one = getByte(addr)
    return str

def dexGetStringId(dexfile, idx):
    return getDword(dexfile.pStringIds+4*idx)

def dexStringById(dexfile, idx):
    offset = dexGetStringId(dexfile, idx)
    return dexGetStringData(dexfile, offset)

def dexGetTypeId(dexfile, idx):
    return getDword(dexfile.pTypeIds+4*idx)

def dexStringByTypeIdx(dexfile, idx):
    return dexStringById(dexfile, dexGetTypeId(dexfile, idx))

def dexGetClassDescriptor(dexfile, classdef):
    return dexStringByTypeIdx(dexfile, classdef.classIdx)

def slashtodot(str):
    ret = ""
    for i in str:
        if i == '/':
            ret += '.'
        elif i == ';':
            continue
        else:
            ret += i
    return ret

def rightshift(value, n):
    mask = 0x80000000
    check = value & mask
    if check != mask:
        return value >> n
    else:
        submask = mask
        for loop in range(0, n):
            submask = (submask | (mask >> loop))
        strdata = struct.pack("I", submask | (value >> n))
        ret = struct.unpack("i", strdata)[0]
        return ret

def readunsignedleb128(addr):
    res = getByte(addr)
    len = 1
    if res > 0x7f:
        cur = getByte(addr + 1)
        res = (res & 0x7f) | ((cur & 0x7f) << 7)
        len = 2
        if cur > 0x7f:
            cur = getByte(addr + 2)
            res |= (cur & 0x7f) << 14
            len = 3
            if cur > 0x7f:
                cur = getByte(addr + 3)
                res |= (cur & 0x7f) << 21
                len = 4
                if cur > 0x7f:
                    cur = getByte(addr + 4)
                    res |= cur << 28
                    len = 5
    return res, len

def readsignedleb128(addr):
    res = getByte(addr)
    len = 1
    if res <= 0x7f:
        res = rightshift((res << 25), 25)
    else:
        cur = getByte(addr + 1)
        res = (res & 0x7f) | ((cur & 0x7f) << 7)
        len = 2
        if cur <= 0x7f:
            res = rightshift((res << 18), 18)
        else:
            cur = getByte(addr + 2)
            res |= (cur & 0x7f) << 14
            len = 3
            if cur <= 0x7f:
                res = rightshift((res << 11), 11)
            else:
                cur = getByte(addr + 3)
                res |= (cur & 0x7f) << 21
                len = 4
                if cur <= 0x7f:
                    res = rightshift((res << 4), 4)
                else:
                    cur = getByte(addr + 4)
                    res |= cur << 28
                    len = 5
    return res, len

def writesignedleb128(num, file):
    if num >= 0:
        writeunsignedleb128(num, file)
    else:
        mask = 0x80000000
        for i in range(0, 32):
            tmp = num & mask
            mask >>= 1
            if tmp == 0:
                break
        loop = 32 - i + 1
        while loop > 7:
            cur = num & 0x7f | 0x80
            num >>= 7
            file.write(struct.pack("B", cur))
            loop -= 7
        cur = num & 0x7f
        file.write(struct.pack("B", cur))

def signedleb128forlen(num):
    if num >= 0:
        return unsignedleb128forlen(num)
    else:
        mask = 0x80000000
        for i in range(0, 32):
            tmp = num & mask
            mask >>= 1
            if tmp == 0:
                break
        loop = 32 - i + 1
        if loop % 7 == 0:
            return loop / 7
        else:
            return loop / 7 + 1

def writeunsignedleb128(num, file):
    if num <= 0x7f:
        file.write(struct.pack("B", num))
    else:
        cur = num & 0x7F | 0x80
        file.write(struct.pack("B", cur))
        num >>= 7
        if num <= 0x7f:
            file.write(struct.pack("B", num))
        else:
            cur = num & 0x7f | 0x80
            file.write(struct.pack("B", cur))
            num >>= 7
            if num <= 0x7f:
                file.write(struct.pack("B", num))
            else:
                cur = num & 0x7f | 0x80
                file.write(struct.pack("B", cur))
                num >>= 7
                if num <= 0x7f:
                    file.write(struct.pack("B", num))
                else:
                    cur = num & 0x7f | 0x80
                    file.write(struct.pack("B", cur))
                    num >>= 7
                    file.write(struct.pack("B", num))

def unsignedleb128forlen(num):
    len = 1
    temp = num
    while num > 0x7f:
        len += 1
        num >>= 7
    if len > 5:
        print("error for unsignedleb128forlen", temp)
    return len

def readunsignedleb128p1(addr):
    res, len = readunsignedleb128(addr)
    return res - 1, len

def writeunsignedleb128p1(num, file):
    writeunsignedleb128(num+1, file)

def unsignedleb128p1forlen(num):
    return unsignedleb128forlen(num+1)

class DvmDex:
    def __init__(self):
        self.pDexFile = 0
        self.pHeader = 0    # it is a clone of dex file
        # just for now

    def dump(self, addr):
        self.pDexFile = getDword(addr)
        self.pHeader = getDword(addr + 4)

    def printf(self):
        # i wanna see the diff between the pDexFile.dexfile and pheader
        print("dexfile addr is: ", hex(self.pDexFile))
        print("header addr is: ", hex(self.pHeader))

class DexFile:
    def __init__(self):
        self.pOptHeader = 0
        self.pHeader = 0
        self.pStringIds = 0
        self.pTypeIds = 0
        self.pFieldIds = 0
        self.pMethodIds = 0
        self.pProtoIds = 0
        self.pClassDefs = 0
        self.pLinkData = 0
        self.baseAddr = 0
        self.OptHeader = OptHeader()
        self.dexHeader = DexHeader()

    def dump(self, addr):
        global baseAddr
        self.pOptHeader = getDword(addr)
        self.pHeader = getDword(addr + 4)
        self.pStringIds = getDword(addr + 8)
        self.pTypeIds = getDword(addr + 12)
        self.pFieldIds = getDword(addr + 16)
        self.pMethodIds = getDword(addr + 20)
        self.pProtoIds = getDword(addr + 24)
        self.pClassDefs = getDword(addr + 28)
        self.pLinkData = getDword(addr + 32)
        self.baseAddr = getDword(addr + 44)
        baseAddr = self.baseAddr
        self.OptHeader.dump(self.pOptHeader)
        self.dexHeader.dump(self.pHeader)
        self.fixDexHeader()

    def fixDexHeader(self):
        self.dexHeader.stringIdsOff = self.pStringIds - self.pHeader
        self.dexHeader.typeIdsOff = self.pTypeIds - self.pHeader
        self.dexHeader.fieldIdsOff = self.pFieldIds - self.pHeader
        self.dexHeader.methodIdsOff = self.pMethodIds - self.pHeader
        self.dexHeader.protoIdsOff = self.pProtoIds - self.pHeader
        self.dexHeader.classDefsOff = self.pClassDefs - self.pHeader
        if self.dexHeader.dataOff == 0:
            self.dexHeader.dataOff = self.dexHeader.classDefsOff + self.dexHeader.classDefsSize*32
            # We should figure out a new method to fix the data size
            # self.dexHeader.dataSize = 0x5DD28000 - self.baseAddr - self.dexHeader.dataOff

    def lookupClass(self, type):
        num_class_def = self.dexHeader.classDefsSize
        print "num class def:", num_class_def
        for i in range(num_class_def):
            classdef = DexClassDef()
            classdef.dump(self.pClassDefs+32*i)
            descriptor = dexGetClassDescriptor(self, classdef)
            if descriptor == type:
                print "Find the class", descriptor
                if classdef.classDataOff == 0:
                    print "classDataOff is 0"
                    return
                classdata = ClassdataItem()
                classdata.dump(int(self.baseAddr+classdef.classDataOff) & 0xffffffff)
                print "direct methods:", classdata.direct_methods_size
                for j in range(classdata.direct_methods_size):
                    method = classdata.direct_methods[j]
                    method.printf()
                print "virtual methods:", classdata.virtual_methods_size
                for j in range(classdata.virtual_methods_size):
                    method = classdata.virtual_methods[j]
                    method.printf()

    def printf(self):
        print("dex head addr: ", hex(self.pHeader))
        print("dex head addr: ", hex(self.baseAddr))

class DexClassDef:
    def __init__(self):
        self.classIdx = 0
        self.accessFlags = 0
        self.superclassIdx = 0
        self.interfacesOff = 0
        self.sourceFileIdx = 0
        self.annotationsOff = 0
        self.classDataOff = 0
        self.staticValuesOff = 0

    def dump(self, addr):
        self.classIdx = getDword(addr)
        self.accessFlags = getDword(addr + 4)
        self.superclassIdx = getDword(addr + 8)
        self.interfacesOff = getDword(addr + 12)
        self.sourceFileIdx = getDword(addr + 16)
        self.annotationsOff = getDword(addr + 20)
        self.classDataOff = getDword(addr + 24)
        self.staticValuesOff = getDword(addr + 28)

    def copytofile(self, file):
        file.write(struct.pack("I", self.classIdx))
        file.write(struct.pack("I", self.accessFlags))
        file.write(struct.pack("I", self.superclassIdx))
        file.write(struct.pack("I", self.interfacesOff))
        file.write(struct.pack("I", self.sourceFileIdx))
        file.write(struct.pack("I", self.annotationsOff))
        file.write(struct.pack("I", self.classDataOff))
        file.write(struct.pack("I", self.staticValuesOff))

class DexHeader:
    def __init__(self):
        self.magic = []
        self.checksum = 0
        self.signature = []
        self.fileSize = 0
        self.headerSize = 0
        self.endianTag = 0
        self.linkSize = 0
        self.linkOff = 0
        self.mapOff = 0
        self.stringIdsSize = 0
        self.stringIdsOff = 0
        self.typeIdsSize = 0
        self.typeIdsOff = 0
        self.protoIdsSize = 0
        self.protoIdsOff = 0
        self.fieldIdsSize = 0
        self.fieldIdsOff = 0
        self.methodIdsSize = 0
        self.methodIdsOff = 0
        self.classDefsSize = 0
        self.classDefsOff = 0
        self.dataSize = 0   # have it
        self.dataOff = 0    # have it

    def dump(self, addr):
        len = 0
        while len < 8:
            self.magic.append(getByte(addr + len))
            len += 1
        self.checksum = getDword(addr + 8)
        len = 0
        while len < 20:
            self.signature.append(getByte(addr + 12 + len))
            len += 1
        self.fileSize = getDword(addr + 32)
        self.headerSize = getDword(addr + 36)
        self.endianTag = getDword(addr + 40)
        self.linkSize = getDword(addr + 44)
        self.linkOff = getDword(addr + 48)
        self.mapOff = getDword(addr + 52)
        self.stringIdsSize = getDword(addr + 56)
        self.stringIdsOff = getDword(addr + 60)
        self.typeIdsSize = getDword(addr + 64)
        self.typeIdsOff = getDword(addr + 68)
        self.protoIdsSize = getDword(addr + 72)
        self.protoIdsOff = getDword(addr + 76)
        self.fieldIdsSize = getDword(addr + 80)
        self.fieldIdsOff = getDword(addr + 84)
        self.methodIdsSize = getDword(addr + 88)
        self.methodIdsOff = getDword(addr + 92)
        self.classDefsSize = getDword(addr + 96)
        self.classDefsOff = getDword(addr + 100)
        self.dataSize = getDword(addr + 104)
        self.dataOff = getDword(addr + 108)

    def printf(self):
        print "string off", self.stringIdsOff
        print "type off", self.typeIdsOff
        print "proto off", self.protoIdsOff
        print "field off", self.fieldIdsOff
        print "method off", self.methodIdsOff
        print "classdef off", self.classDefsOff
        print "classdef size:", self.classDefsSize

    def copytofile(self, file):
        len = 0
        while len < 8:
            file.write(struct.pack("B", self.magic[len]))
            len += 1
        file.write(struct.pack("I", self.checksum))
        len = 0
        while len < 20:
            file.write(struct.pack("B", self.signature[len]))
            len += 1
        file.write(struct.pack("I", self.fileSize))
        file.write(struct.pack("I", self.headerSize))
        file.write(struct.pack("I", self.endianTag))
        file.write(struct.pack("I", self.linkSize))
        file.write(struct.pack("I", self.linkOff))
        file.write(struct.pack("I", self.mapOff))
        file.write(struct.pack("I", self.stringIdsSize))
        file.write(struct.pack("I", self.stringIdsOff))
        file.write(struct.pack("I", self.typeIdsSize))
        file.write(struct.pack("I", self.typeIdsOff))
        file.write(struct.pack("I", self.protoIdsSize))
        file.write(struct.pack("I", self.protoIdsOff))
        file.write(struct.pack("I", self.fieldIdsSize))
        file.write(struct.pack("I", self.fieldIdsOff))
        file.write(struct.pack("I", self.methodIdsSize))
        file.write(struct.pack("I", self.methodIdsOff))
        file.write(struct.pack("I", self.classDefsSize))
        file.write(struct.pack("I", self.classDefsOff))
        file.write(struct.pack("I", self.dataSize))
        file.write(struct.pack("I", self.dataOff))

class OptHeader:
    def __init__(self):
        self.magic = []   # take 8 bytes
        self.dexoffset = 0
        self.dexLength = 0
        self.depsOffset = 0
        self.depsLength = 0
        self.optOffset = 0
        self.optLength = 0
        self.flag = 0
        self.checksum = 0

    def dump(self, addr):
        if addr == 0:
            return
        len = 0
        while len < 8:
            self.magic.append(getByte(addr + len))
            len += 1
        self.dexoffset = getDword(addr+8)
        self.dexLength = getDword(addr+12)
        self.depsOffset = getDword(addr+16)
        self.depsLength = getDword(addr+20)
        self.optOffset = getDword(addr+24)
        self.optLength = getDword(addr+28)
        self.flag = getDword(addr+32)
        self.checksum = getDword(addr+36)

    def copytofile(self, file):
        len = 0
        while len < 8:
            file.write(struct.pack("B", self.magic[len]))
            len += 1
        file.write(struct.pack("I", self.dexoffset))
        file.write(struct.pack("I", self.dexLength))
        file.write(struct.pack("I", self.depsOffset))
        file.write(struct.pack("I", self.depsLength))
        file.write(struct.pack("I", self.optOffset))
        file.write(struct.pack("I", self.optLength))
        file.write(struct.pack("I", self.flag))
        file.write(struct.pack("I", self.checksum))

class ClassdataItem:
    def __init__(self):
        self.len = 0
        self.static_field_size = 0
        self.instance_fields_size = 0
        self.direct_methods_size = 0
        self.virtual_methods_size = 0
        self.static_fields = []
        self.instance_fields = []
        self.direct_methods = []
        self.virtual_methods = []

    def dump(self, addr):
        self.static_field_size, length = readunsignedleb128(addr)
        self.len += length
        self.instance_fields_size, length = readunsignedleb128(addr + self.len)
        self.len += length
        self.direct_methods_size, length = readunsignedleb128(addr + self.len)
        self.len += length
        self.virtual_methods_size, length = readunsignedleb128(addr + self.len)
        self.len += length
        for i in range(0, self.static_field_size):
            field = Encodedfield()
            field.dump(addr + self.len)
            self.len += field.len
            self.static_fields.append(field)
        for i in range(0, self.instance_fields_size):
            field = Encodedfield()
            field.dump(addr + self.len)
            self.len += field.len
            self.instance_fields.append(field)
        for i in range(0, self.direct_methods_size):
            method = Encodedmethod()
            method.dump(addr + self.len)
            self.len += method.len
            self.direct_methods.append(method)
        for i in range(0, self.virtual_methods_size):
            method = Encodedmethod()
            method.dump(addr + self.len)
            self.len += method.len
            self.virtual_methods.append(method)

    def recallLength(self):
        self.len = 0
        self.len += unsignedleb128forlen(self.static_field_size)
        self.len += unsignedleb128forlen(self.instance_fields_size)
        self.len += unsignedleb128forlen(self.direct_methods_size)
        self.len += unsignedleb128forlen(self.virtual_methods_size)
        for i in range(0, self.static_field_size):
            self.len += self.static_fields[i].len
        for i in range(0, self.instance_fields_size):
            self.len += self.instance_fields[i].len
        for i in range(0, self.direct_methods_size):
            self.len += self.direct_methods[i].recallLength()
        for i in range(0, self.virtual_methods_size):
            self.len += self.virtual_methods[i].recallLength()
        return self.len

    def copytofile(self, file):
        writeunsignedleb128(self.static_field_size, file)
        writeunsignedleb128(self.instance_fields_size, file)
        writeunsignedleb128(self.direct_methods_size, file)
        writeunsignedleb128(self.virtual_methods_size, file)
        for i in range(0, self.static_field_size):
            self.static_fields[i].copytofile(file)
        for i in range(0, self.instance_fields_size):
            self.instance_fields[i].copytofile(file)
        for i in range(0, self.direct_methods_size):
            self.direct_methods[i].copytofile(file)
        for i in range(0, self.virtual_methods_size):
            self.virtual_methods[i].copytofile(file)

class Encodedfield:
    def __init__(self):
        self.len = 0
        self.field_idx_diff = 0
        self.access_flags = 0
        self.field_idx = 0      # need to set later

    def dump(self, addr):
        self.field_idx_diff, length = readunsignedleb128(addr)
        self.len += length
        self.access_flags, length = readunsignedleb128(addr + self.len)
        self.len += length

    def copytofile(self, file):
        writeunsignedleb128(self.field_idx_diff, file)
        writeunsignedleb128(self.access_flags, file)

class Encodedmethod:
    def __init__(self):
        self.len = 0
        self.method_idx_diff = 0
        self.access_flags = 0
        self.code_off = 0
        self.method_idx = 0

    def dump(self, addr):
        self.method_idx_diff, length = readunsignedleb128(addr)
        self.len += length
        self.access_flags, length = readunsignedleb128(addr + self.len)
        self.len += length
        self.code_off, length = readunsignedleb128(addr + self.len)
        self.len += length

    def recallLength(self):
        self.len = 0
        self.len += unsignedleb128forlen(self.method_idx_diff)
        self.len += unsignedleb128forlen(self.access_flags)
        self.len += unsignedleb128forlen(self.code_off)
        return self.len

    def copytofile(self, file):
        writeunsignedleb128(self.method_idx_diff, file)
        writeunsignedleb128(self.access_flags, file)
        writeunsignedleb128(self.code_off, file)

    def printf(self):
        print "code offset:", self.code_off
        print "access flag:", self.access_flags

# alignment: 4bytes
class CodeItem:
    def __init__(self):
        self.len = 0
        self.register_size = 0
        self.ins_size = 0
        self.outs_size = 0
        self.tries_size = 0
        self.debug_info_off = 0
        self.insns_size = 0
        self.insns = []
        self.debugRef = None
        self.padding = 0
        self.tries = []
        self.handler = None

    def dump(self, addr):
        self.register_size = getWord(addr)  # 2
        self.ins_size = getWord(addr + 2)   # 0
        self.outs_size = getWord(addr + 4)  # 0x4187
        self.tries_size = getWord(addr + 6)     # 0x13
        self.debug_info_off = getDword(addr + 8)    # 0xD
        self.insns_size = getDword(addr + 12)   # 0x22
        self.len += 16
        for i in range(0, self.insns_size):
            self.insns.append(getWord(addr + self.len + 2 * i))
        self.len += 2 * self.insns_size
        if self.tries_size != 0 and self.insns_size % 2 == 1:
            self.len += 2
        for i in range(0, self.tries_size):
            tryitem = TryItem()
            tryitem.dump(addr + self.len + 8 * i)
            self.tries.append(tryitem)
        self.len += 8 * self.tries_size
        if self.tries_size != 0:
            self.handler = EncodedhandlerList()
            self.handler.dump(addr + self.len)
            self.len += self.handler.len
        # align = self.len % 4
        # if align != 0:
        #     self.len += (4 - align)

class TryItem:
    def __init__(self):
        self.start = 0
        self.len = 8
        self.start_addr = 0
        self.insn_count = 0
        self.handler_off = 0

    def dump(self, addr):
        self.start = addr
        self.start_addr = getDword(addr)
        self.insn_count = getWord(addr + 4)
        self.handler_off = getWord(addr + 6)

class EncodedhandlerList:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.size = 0
        self.list = []

    def dump(self, addr):
        self.start = addr
        self.size, length = readunsignedleb128(addr)
        self.len += length
        for i in range(0, self.size):
            handler = EncodedhandlerItem()
            handler.dump(addr + self.len)
            self.len += handler.len
            self.list.append(handler)

class EncodedhandlerItem:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.size = 0
        self.handlers = []
        self.catch_all_addr = 0

    def dump(self, addr):
        self.start = addr
        self.size, length = readsignedleb128(addr)
        self.len += length
        for i in range(0, abs(self.size)):
            pair = EncodedTypeAddrPair()
            pair.dump(addr + self.len)
            self.len += pair.len
            self.handlers.append(pair)
        if self.size <= 0:
            self.catch_all_addr, length = readunsignedleb128(addr + self.len)
            self.len += length

class EncodedTypeAddrPair:
    def __init__(self):
        self.type_idx = 0
        self.addr = 0
        self.len = 0

    def dump(self, addr):
        self.type_idx, length = readunsignedleb128(addr)
        self.len += length
        self.addr, length = readunsignedleb128(addr + length)
        self.len += length

address = int(0x5d4e8020)   # DexFile address
dexfile = DexFile()
dexfile.dump(address)
dexfile.dexHeader.printf()
dexfile.lookupClass("Lcom/baidu/lbsapi/auth/LBSAuthManagerListener;")
# dexfile.copytofile()
