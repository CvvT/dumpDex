__author__ = 'CwT'

from idaapi import *
from idautils import *
from idc import *
import struct
import os
import hashlib

Access_Flag = {'public': 1, 'private': 2, 'protected': 4, 'static': 8, 'final': 0x10,
               'synchronized': 0x20, 'volatile': 0x40, 'bridge': 0x40, 'transient': 0x80,
               'varargs': 0x80, 'native': 0x100, 'interface': 0x200, 'abstract': 0x400,
               'strictfp': 0x800, 'synthetic': 0x1000, 'annotation': 0x2000, 'enum': 0x4000,
               'constructor': 0x10000, 'declared_synchronized': 0x20000}

TypeDescriptor = {'void': 'V', 'boolean': 'Z', 'byte': 'B', 'short': 'S', 'char': 'C',
                  'int': 'I', 'long': 'J', 'float': 'F', 'double': 'D', 'boolean[]': '[Z',
                  'byte[]': '[B', 'short[]': '[S', 'char[]': '[C', 'int[]': 'I',
                  'long[]': '[J', 'float[]': '[F', 'double[]': 'D'}

ShortyDescriptor = {'void': 'V', 'boolean': 'Z', 'byte': 'B', 'short': 'S', 'char': 'C',
                    'int': 'I', 'long': 'J', 'float': 'F', 'double': 'D'}

ACSII = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, '0': 0,
         'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}

def checksum(f, len):
    a = 1
    b = 0
    f.seek(12)
    print("file size is :", len)
    for i in range(12, len):
        onebyte = struct.unpack("B", f.read(1))[0]
        a = (a + onebyte) % 65521
        b = (b + a) % 65521
    return b << 16 | a

def get_file_sha1(f):
    f.seek(32)  # skip magic, checksum, sha
    sha = hashlib.sha1()
    while True:
        data = f.read(1024)
        if not data:
            break
        sha.update(data)
    return sha.hexdigest()

def getDword(addr):
    return Dword(addr)

def getByte(addr):
    return Byte(addr)

def getWord(addr):
    return Word(addr)

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

def getutf8str(addr):
    string = []
    while 1:
        onebyte = getByte(addr)
        addr += 1
        if onebyte == 0:
            break
        string.append(onebyte)
    return bytearray(string).decode("utf-8")

def getstr(bytes):
    return bytearray(bytes).decode("utf-8")

class DexorJar:
    def __init__(self):
        self.pfileName = 0
        self.isDex = 0
        self.okaytoFree = 0     # do not care
        self.pRawDexFile = 0
        self.pJarFile = 0
        self.pDexMemory = 0  # do not care

    def dump(self, addr):
        self.pfileName = getDword(addr)
        self.isDex = getByte(addr + 4)
        self.pRawDexFile = getDword(addr + 8)
        self.pJarFile = getDword(addr + 12)

    def printf(self):
        str = ""
        baseaddr = self.pfileName
        onebyte = getByte(baseaddr)
        while onebyte != 0:
            str += chr(onebyte)
            baseaddr += 1
            onebyte = getByte(baseaddr)
        print("filename is:", str)
        if self.isDex > 0:
            print("it's a dex file, addr: ", hex(self.pRawDexFile))
        else:
            print("it's a jar file, addr: ", hex(self.pJarFile))

class JarFile:
    def __init__(self):
        self.archive = None     # do not care
        self.pcacheFileName = 0
        self.pDvmDex = 0

    def dump(self, addr):
        self.pcacheFileName = getDword(addr + 36)
        self.pDvmDex = getDword(addr + 40)

    def printf(self):
        str = ""
        baseaddr = self.pcacheFileName
        one = getByte(baseaddr)
        while one != 0:
            str += chr(one)
            baseaddr += 1
            one = getByte(baseaddr)
        print("cache file name is : ", str)
        print("DvmDex addr is :", hex(self.pDvmDex))

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

global baseAddr

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
        self.dexheader = DexHeader()
        self.dexmaplist = DexMapList()

    def dump(self, addr):
        global baseAddr
        self.pOptHeader = getDword(addr)
        self.pHeader = getDword(addr + 4)
        self.pStringIds = getDword(addr + 8)
        self.pTypeIds = getDword(addr + 12)
        self.pFieldIds = getDword(addr + 16)
        self.pMethodIds = getDword(addr + 20)
        self.pProtoIds = getDword(addr + 24)
        self.pProtoIds = getDword(addr + 28)
        self.pLinkData = getDword(addr + 32)
        self.baseAddr = getDword(addr + 44)
        baseAddr = self.baseAddr
        self.dexheader.dump(self.pHeader)
        self.dexmaplist.dump(self.dexheader.mapOff)
        self.dexmaplist.dexmapitem[0].item.append(self.dexheader)
        print("end build dex and start to get reference")
        self.dexmaplist.getreference()

    def makeoffset(self):
        off = self.dexmaplist.makeoff()
        align = off % 4
        if align != 0:
            off += (4 - align)
        self.dexheader.makeoffset(self.dexmaplist.dexmapitem)
        self.dexheader.fileSize = off
        self.dexheader.dataSize = off - self.dexheader.mapOff

    def copytofile(self, filename):
        if os.path.exists(filename):
            os.remove(filename)
        file = open(filename, 'wb+')
        file.seek(0, 0)
        self.makeoffset()
        self.dexmaplist.copy(file)
        rest = self.dexheader.fileSize -file.tell()
        for i in range(0, rest):
            file.write(struct.pack("B", 0))
        file_sha = get_file_sha1(file)
        tmp = bytes(file_sha)
        i = 0
        file.seek(12)
        while i < 40:
            num = (ACSII[tmp[i]] << 4) + ACSII[tmp[i+1]]
            file.write(struct.pack("B", num))
            i += 2
        csum = checksum(file, self.dexheader.fileSize)
        print("checksum:", hex(csum), "file size:", self.dexheader.fileSize)
        file.seek(8)
        file.write(struct.pack("I", csum))
        file.close()

    def printf(self):
        print("dex head addr: ", hex(self.pHeader))
        print("dex head addr: ", hex(self.baseAddr))

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
        self.dataSize = 0
        self.dataOff = 0

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
        self.fieldIdsOff = getDword(addr + 88)
        self.methodIdsSize = getDword(addr + 92)
        self.methodIdsOff = getDword(addr + 96)
        self.classDefsSize = getDword(addr + 100)
        self.classDefsOff = getDword(addr + 104)
        self.dataSize = getDword(addr + 108)
        self.dataOff = getDword(addr + 112)

    def makeoffset(self, dexmaplist):
        self.stringIdsSize = dexmaplist[1].size
        self.stringIdsOff = dexmaplist[1].offset
        self.typeIdsSize = dexmaplist[2].size
        self.typeIdsOff = dexmaplist[2].offset
        self.protoIdsSize = dexmaplist[3].size
        self.protoIdsOff = dexmaplist[3].offset
        self.fieldIdsSize = dexmaplist[4].size
        self.fieldIdsOff = dexmaplist[4].offset
        self.methodIdsSize = dexmaplist[5].size
        self.methodIdsOff = dexmaplist[5].offset
        self.classDefsSize = dexmaplist[6].size
        self.classDefsOff = dexmaplist[6].offset
        self.dataOff = dexmaplist[0x1000].offset
        self.dataSize = 0
        self.mapOff = dexmaplist[0x1000].offset
        self.fileSize = 0

    def copytofile(self, file):
        file.seek(0, 0)
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

class DexMapList:
    Seq = (0, 1, 2, 3, 4, 5, 6, 0x1000, 0x1001, 0x1002, 0x1003, 0x2001, 0x2000, 0x2002,
           0x2003, 0x2004, 0x2005, 0x2006)

    def __init__(self):
        self.start = 0
        self.size = 0
        self.dexmapitem = {}

    def dump(self, offset):
        self.start = offset
        self.size = getDword(offset + baseAddr)
        mapitem = []
        for i in range(0, self.size):
            item = DexMapItem()
            item.dump(offset + baseAddr + 4 + i * 12)
            mapitem.append(item)
            item.printf()
        for i in range(0, self.size):
            mapitem[i].setitem(self.dexmapitem)
            self.dexmapitem[mapitem[i].type] = mapitem[i]

    def copy(self, file):
        for i in range(0, len(DexMapList.Seq)):
            index = DexMapList.Seq[i]
            if index in self.dexmapitem.keys():
                print(index, "start at:", file.tell())
                if index != 0x1000:
                    self.dexmapitem[index].copytofile(file)
                else:
                    self.copytofile(file)

    def copytofile(self, file):
        print("output map list", file.tell())
        file.seek(self.start, 0)
        file.write(struct.pack("I", self.size))
        for i in range(0, len(DexMapList.Seq)):
            index = DexMapList.Seq[i]
            if index in self.dexmapitem.keys():
                # print(self.dexmapitem[index].type)
                file.write(struct.pack("H", self.dexmapitem[index].type))
                file.write(struct.pack("H", self.dexmapitem[index].unused))
                file.write(struct.pack("I", self.dexmapitem[index].size))
                file.write(struct.pack("I", self.dexmapitem[index].offset))

    def makeoff(self):
        off = 0
        for i in range(0, len(DexMapList.Seq)):
            index = DexMapList.Seq[i]
            if index in self.dexmapitem.keys():
                align = off % 4
                if align != 0:
                    off += (4 - align)
                if index != 0x1000:
                    off = self.dexmapitem[index].makeoffset(off)
                else:
                    off = self.makeoffset(off)
        return off

    def makeoffset(self, off):
        self.start = off
        off += (4 + self.size * 12)
        self.dexmapitem[0x1000].offset = self.start
        return off

    def getreference(self):
        self.dexmapitem[1].getref(self.dexmapitem)
        print("string id get ref done")
        self.dexmapitem[3].getref(self.dexmapitem)
        print("proto id get ref done")
        self.dexmapitem[6].getref(self.dexmapitem)
        print("class def get ref done")
        if 0x1002 in self.dexmapitem.keys():
            self.dexmapitem[0x1002].getref(self.dexmapitem)
            print("annotation set ref get ref done")
        if 0x1003 in self.dexmapitem.keys():
            self.dexmapitem[0x1003].getref(self.dexmapitem)
            print("annotation set get ref done")
        # self.dexmapitem[0x2000].getref(self.dexmapitem)
        self.dexmapitem[0x2001].getref(self.dexmapitem)
        print("code item get ref done")
        if 0x2006 in self.dexmapitem.keys():
            self.dexmapitem[0x2006].getref(self.dexmapitem)
            print("annotation dir item get ref done")

    def getrefbystr(self, str):
        return self.dexmapitem[0x2002].getrefbystr(str)

    def printf(self, index):
        print ("DexMapList:")
        print ("size: ", self.size)
        for i in self.dexmapitem:
            self.dexmapitem[i].printf(index)

class DexMapItem:
    Constant = {0: 'TYPE_HEADER_ITEM', 1: 'TYPE_STRING_ID_ITEM', 2: 'TYPE_TYPE_ID_ITEM',
                3: 'TYPE_PROTO_ID_ITEM', 4: 'TYPE_FIELD_ID_ITEM', 5: 'TYPE_METHOD_ID_ITEM',
                6: 'TYPE_CLASS_DEF_ITEM', 0x1000: 'TYPE_MAP_LIST', 0x1001: 'TYPE_TYPE_LIST',
                0x1002: 'TYPE_ANNOTATION_SET_REF_LIST', 0x1003: 'TYPE_ANNOTATION_SET_ITEM',
                0x2000: 'TYPE_CLASS_DATA_ITEM', 0x2001: 'TYPE_CODE_ITEM', 0x2002: 'TYPE_STRING_DATA_ITEM',
                0x2003: 'TYPE_DEBUG_INFO_ITEM', 0x2004: 'TYPE_ANNOTATION_ITEM', 0x2005: 'TYPE_ENCODED_ARRAY_ITEM',
                0x2006: 'TYPE_ANNOTATIONS_DIRECTORY_ITEM'}

    def __init__(self):
        self.type = 0
        self.unused = 0
        self.size = 0
        self.offset = 0
        self.item = []
        self.len = 0

    def dump(self, addr):
        self.type = getWord(addr)
        self.unused = getWord(addr + 2)
        self.size = getDword(addr + 4)
        self.offset = getDword(addr + 8)

    def copytofile(self, file):
        file.seek(self.offset, 0)
        if self.type <= 0x2006:
            align = file.tell() % 4
            if align != 0:
                for i in range(0, 4-align):
                    file.write(struct.pack("B", 0))
            print("copytofile:", DexMapItem.Constant[self.type], file.tell())
            for i in range(0, self.size):
                if self.type == 0x2000:
                    print("index, offset", i, hex(self.item[i].start), self.item[i].static_field_size, self.item[i].instance_fields_size, self.item[i].direct_methods_size, self.item[i].virtual_methods_size)
                self.item[i].copytofile(file)
                # if self.type == 0x2002:
                #     print("for debug", i, getstr(self.item[i].str))

    def printf(self):
        print ("type: ", DexMapItem.Constant[self.type])
        print ("size: ", self.size)
        print ("offset: ", hex(self.offset), hex(self.offset + baseAddr))
        # if self.type == index:
        #     for i in range(0, self.size):
        #         self.item[i].printf()
        #     print ()

    def setitem(self, dexmapitem):
        self.printf()
        addr = baseAddr + self.offset
        for i in range(0, self.size):
            if self.type == 1:  # string
                dexstringid = DexStringID()
                dexstringid.dump(addr + 4 * i)
                self.item.append(dexstringid)
            elif self.type == 2:
                dextypeid = DexTypeID()
                dextypeid.dump(addr + 4 * i, dexmapitem[1].item)
                self.item.append(dextypeid)  # make sure has already build string table
            elif self.type == 3:
                dexprotoid = DexProtoId()
                dexprotoid.dump(addr + 12 * i, dexmapitem[1].item, dexmapitem[2].item)
                self.item.append(dexprotoid)
            elif self.type == 4:
                dexfieldid = DexFieldId()
                dexfieldid.dump(addr + 8 * i, dexmapitem[1].item, dexmapitem[2].item)
                self.item.append(dexfieldid)
            elif self.type == 5:
                dexmethodid = DexMethodId()
                dexmethodid.dump(addr + 8 * i, dexmapitem[1].item, dexmapitem[2].item)
                self.item.append(dexmethodid)
            elif self.type == 6:
                dexclassdef = DexClassDef()
                dexclassdef.dump(addr + 32 * i, dexmapitem[1].item, dexmapitem[2].item)
                self.item.append(dexclassdef)
            elif self.type == 0x1001:   # TYPE_TYPE_LIST
                typeitem = TypeItem()
                typeitem.dump(addr, dexmapitem[2].item)
                addr += typeitem.len
                self.item.append(typeitem)
            elif self.type == 0x1002:   # TYPE_ANNOTATION_SET_REF_LIST
                annoitem = AnnotationsetrefList()
                annoitem.dump(addr)
                addr += annoitem.len
                self.item.append(annoitem)
            elif self.type == 0x1003:   # TYPE_ANNOTATION_SET_ITEM
                annoitem = AnnotationsetItem()
                annoitem.dump(addr)
                addr += annoitem.len
                self.item.append(annoitem)
            elif self.type == 0x2000:   # TYPE_CLASS_DATA_ITEM
                classitem = ClassdataItem()
                classitem.dump(addr, dexmapitem[0x2001].item)
                addr += classitem.len
                self.item.append(classitem)
            # elif self.type == 0x2001:   # TYPE_CODE_ITEM
            #     codeitem = CodeItem()
            #     codeitem.dump(addr)
            #     addr += codeitem.len
            #     self.item.append(codeitem)
            elif self.type == 0x2002:   # TYPE_STRING_DATA_ITEM
                stringdata = StringData()
                stringdata.dump(addr)
                addr += stringdata.len
                self.item.append(stringdata)
            elif self.type == 0x2003:   # TYPE_DEBUG_INFO_ITEM
                debuginfo = DebugInfo()
                debuginfo.dump(addr)
                addr += debuginfo.len
                self.item.append(debuginfo)
            elif self.type == 0x2004:   # TYPE_ANNOTATION_ITEM
                item = AnnotationItem()
                item.dump(addr)
                addr += item.len
                self.item.append(item)
            elif self.type == 0x2005:   # TYPE_ENCODED_ARRAY_ITEM
                arrayitem = EncodedArrayItem()
                arrayitem.dump(addr)
                addr += arrayitem.len
                self.item.append(arrayitem)
            elif self.type == 0x2006:  # TYPE_ANNOTATIONS_DIRECTORY_ITEM
                dirItem = AnnotationsDirItem()
                dirItem.dump(addr)
                addr += dirItem.len
                self.item.append(dirItem)

    def makeoffset(self, off):
        if self.type < 0x2000 or self.type == 0x2001 or self.type == 0x2006:
            align = off % 4
            if align != 0:
                off += (4 - align)
        self.offset = off
        if self.type == 0:  # header
            self.len = 112
        elif self.type == 1:    # string id
            self.len = 4 * self.size
        elif self.type == 2:    # type id
            self.len = 4 * self.size
        elif self.type == 3:   # proto id
            self.len = 12 * self.size
        elif self.type == 4:    # field id
            self.len = 8 * self.size
        elif self.type == 5:    # method id
            self.len = 8 * self.size
        elif self.type == 6:    # class def
            self.len = 32 * self.size
        elif self.type == 0x1000:   # map list, resolve specially in dexmaplist class
            pass
        elif 0x1001 <= self.type <= 0x2006:   # type list, annotation ref set list, annotation set item...
            for i in range(0, self.size):
                off = self.item[i].makeoffset(off)
                # if self.type == 0x2002:
                #     print("for debug", i, off)
            self.len = off - self.offset
        if self.type == 0x2000:
            print("the off is:", off)
        if self.type <= 6:
            return off + self.len
        else:
            return off

    def getref(self, dexmaplist):
        for i in range(0, self.size):
            self.item[i].getreference(dexmaplist)

    def getreference(self, offset):   # offset
        if offset == 0:
            return None
        i = 0
        for i in range(0, self.size):
            if self.item[i].start == offset + baseAddr:
                return self.item[i]
        # if i >= self.size:
            # os._exit(offset)
        print("failed : don not find the refernce")
        return None

    def getrefbystr(self, str):  # for modify the string data
        if self.type == 0x2002:
            for i in range(0, self.size):
                if getstr(self.item[i].str) == str:
                    return self.item[i]
        else:
            print("error occur here", self.type)
            return None

    def getindexbyname(self, str):  # search for type id item
        for i in range(0, self.size):
            if self.item[i].str == str:
                print("find index of", DexMapItem.Constant[self.type], str)
                return i
        print("did not find it in", DexMapItem.Constant[self.type])
        return -1

    def getindexbyproto(self, short_idx, return_type_idx, param_list, length):  # called by item, index of 3
        for i in range(0, self.size):
            if short_idx == self.item[i].shortyIdx and return_type_idx == self.item[i].returnTypeIdx:
                if self.item[i].ref is not None:
                    if self.item[i].ref.equal(param_list, length):
                        return i
        return -1

class DexStringID:
    def __init__(self):
        self.stringDataOff = 0
        self.size = 0
        self.str = ""
        self.ref = None

    def dump(self, addr):
        self.stringDataOff = getDword(addr)
        self.size, len = readunsignedleb128(self.stringDataOff + baseAddr)
        self.str = getutf8str(self.stringDataOff + len + baseAddr)

    def copytofile(self, file):
        # self.stringDataoff = self.ref.start
        file.write(struct.pack("I", self.ref.start))

    def getreference(self, dexmaplist):
        self.ref = dexmaplist[0x2002].getreference(self.stringDataOff)
        # if self.ref is not None:
        #     self.ref.printf()

    def printf(self):
        print ("size: ", self.size, " str: ", self.str, "dataof: ", self.stringDataOff)

class DexTypeID:
    def __init__(self):
        self.descriptorIdx = 0
        self.str = ""

    def dump(self, addr, str_table):
        self.descriptorIdx = getDword(addr)
        self.str = str_table[self.descriptorIdx].str

    def copytofile(self, file):
        file.write(struct.pack("I", self.descriptorIdx))

    def printf(self):
        print ("type id: ", self.str)

class DexProtoId:
    def __init__(self):
        self.shortyIdx = 0
        self.returnTypeIdx = 0
        self.parametersOff = 0
        self.name = ""
        self.returnstr = ""
        self.ref = None

    def dump(self, addr, str_table, type_table):
        self.shortyIdx = getDword(addr)
        self.returnTypeIdx = getDword(addr + 4)
        self.parametersOff = getDword(addr + 8)
        self.name = str_table[self.shortyIdx].str
        self.returnstr = type_table[self.returnTypeIdx].str

    def copytofile(self, file):
        file.write(struct.pack("I", self.shortyIdx))
        file.write(struct.pack("I", self.returnTypeIdx))
        if self.ref is not None:
            file.write(struct.pack("I", self.ref.start))
        else:
            file.write(struct.pack("I", 0))

    def getreference(self, dexmaplist):
        self.ref = dexmaplist[0x1001].getreference(self.parametersOff)

    def printf(self):
        print ("return Type:", self.returnstr)
        print ("methodname:", self.name)
        if self.ref is not None:
            self.ref.printf()

class DexFieldId:
    def __init__(self):
        self.classIdx = 0
        self.typeIdx = 0
        self.nameIdx = 0
        self.classstr = ""
        self.typestr = ""
        self.name = ""

    def dump(self, addr, str_table, type_table):
        self.classIdx = getWord(addr)
        self.typeIdx = getWord(addr + 2)
        self.nameIdx = getDword(addr + 4)
        self.classstr = type_table[self.classIdx].str
        self.typestr = type_table[self.typeIdx].str
        self.name = str_table[self.nameIdx].str

    def copytofile(self, file):
        file.write(struct.pack("H", self.classIdx))
        file.write(struct.pack("H", self.typeIdx))
        file.write(struct.pack("I", self.nameIdx))

    def printf(self):
        print ("classstr:", self.classstr)
        print ("typestr:", self.typestr)
        print ("name:", self.name)
        print ()

class DexMethodId:
    def __init__(self):
        self.classIdx = 0
        self.protoIdx = 0
        self.nameIdx = 0
        self.classstr = ""
        self.name = ""

    def dump(self, addr, str_table, type_table):
        self.classIdx = getWord(addr)
        self.protoIdx = getWord(addr + 2)
        self.nameIdx = getWord(addr + 4)
        self.classstr = type_table[self.classIdx].str
        self.name = str_table[self.nameIdx].str

    def copytofile(self, file):
        file.write(struct.pack("H", self.classIdx))
        file.write(struct.pack("H", self.protoIdx))
        file.write(struct.pack("I", self.nameIdx))

    def printf(self):
        print ("classstr:", self.classstr)
        print ("name:", self.name)
        print ()

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
        self.classstr = ""
        self.superclassstr = ""
        self.sourceFilestr = ""
        self.interfacesRef = None
        self.annotationsRef = None
        self.classDataRef = None
        self.staticValuesRef = None

    def dump(self, addr, str_table, type_table):
        self.classIdx = getDword(addr)
        self.accessFlags = getDword(addr + 4)
        self.superclassIdx = getDword(addr + 8)
        self.interfacesOff = getDword(addr + 12)
        self.sourceFileIdx = getDword(addr + 16)
        self.annotationsOff = getDword(addr + 20)
        self.classDataOff = getDword(addr + 24)
        self.staticValuesOff = getDword(addr + 28)
        self.classstr = type_table[self.classIdx].str
        self.superclassstr = type_table[self.superclassIdx].str
        if self.sourceFileIdx == 0xFFFFFFFF:
            self.sourceFilestr = "NO_INDEX"
        else:
            self.sourceFilestr = str_table[self.sourceFileIdx].str

    # get class data reference by its name,e.g. Lcom/cc/test/MainActivity;
    def getclassdefref(self, str):
        if self.classstr == str and self.classDataOff > 0:
            return self.classDataRef
        return None

    def copytofile(self, file):
        file.write(struct.pack("I", self.classIdx))
        file.write(struct.pack("I", self.accessFlags))
        file.write(struct.pack("I", self.superclassIdx))
        if self.interfacesRef is not None:
            file.write(struct.pack("I", self.interfacesRef.start))
            # print(self.interfacesRef.start)
        else:
            file.write(struct.pack("I", 0))
        file.write(struct.pack("I", self.sourceFileIdx))
        if self.annotationsRef is not None:
            file.write(struct.pack("I", self.annotationsRef.start))
            # print(self.annotationsRef.start)
        else:
            file.write(struct.pack("I", 0))
        if self.classDataRef is not None:
            file.write(struct.pack("I", self.classDataRef.start))
        else:
            file.write(struct.pack("I", 0))
        if self.staticValuesRef is not None:
            file.write(struct.pack("I", self.staticValuesRef.start))
        else:
            file.write(struct.pack("I", 0))

    def getreference(self, dexmaplist):
        self.interfacesRef = dexmaplist[0x1001].getreference(self.interfacesOff)
        if 0x2006 in dexmaplist.keys():
            self.annotationsRef = dexmaplist[0x2006].getreference(self.annotationsOff)
        self.classDataRef = dexmaplist[0x2000].getreference(self.classDataOff)
        if 0x2005 in dexmaplist.keys():
            self.staticValuesRef = dexmaplist[0x2005].getreference(self.staticValuesOff)

    def printf(self):
        print ("classtype:", self.classIdx, self.classstr)
        print("access flag:", self.accessFlags)
        print ("superclasstype:", self.superclassIdx, self.superclassstr)
        print ("iterface off", self.interfacesOff)
        print("source file index", self.sourceFilestr)
        print("annotations off", self.annotationsOff)
        print("class data off", self.classDataOff)
        print("static values off", self.staticValuesOff)
        if self.interfacesRef is not None:
            self.interfacesRef.printf()
        if self.annotationsRef is not None:
            self.annotationsRef.printf()
        if self.classDataRef is not None:
            self.classDataRef.printf()
        if self.staticValuesRef is not None:
            self.staticValuesRef.printf()

class TypeItem:  # alignment: 4 bytes
    def __init__(self):
        self.start = 0
        self.size = 0
        self.list = []
        self.str = []
        self.len = 0

    def dump(self, addr, type_table):
        self.start = addr
        self.size = getDword(addr)
        self.len = 4 + 2 * self.size
        for i in range(0, self.size):
            self.list.append(getWord(addr + 4 + 2 * i))
            self.str.append(type_table[self.list[i]].str)
        if self.size % 2 == 1:
            getWord(addr + 4 + 2 * self.size)
            self.len += 2

    def copytofile(self, file):
        file.write(struct.pack("I", self.size))
        for i in range(0, self.size):
            file.write(struct.pack("H", self.list[i]))
        if self.size % 2 == 1:
            file.write(struct.pack("H", 0))

    def equal(self, param_list, length):
        if length != self.size:
            return False
        for i in range(0, self.size):
            if param_list[i] != self.str[i]:
                return False
        return True

    def makeoffset(self, off):
        align = off % 4
        if align != 0:
            off += (4 - align)
        self.len = 4 + 2 * self.size
        self.start = off
        return off + self.len

    def printf(self):
        for i in range(0, self.size):
            print (self.list[i], self.str[i])

# alignment: 4bytes
class AnnotationsetItem:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.size = 0
        self.entries = []
        self.ref = []

    def dump(self, addr):
        self.start = addr
        self.size = getDword(addr)
        self.len = 4 + 4 * self.size
        for i in range(0, self.size):
            self.entries.append(getDword(addr + 4 + 4 * i))

    def copytofile(self, file):
        file.write(struct.pack("I", self.size))
        for i in range(0, self.size):
            file.write(struct.pack("I", self.ref[i].start))

    def makeoffset(self, off):
        align = off % 4
        if align != 0:
            off += (4 - align)
        self.start = off
        self.len = 4 + 4 * self.size
        return off + self.len

    def getreference(self, dexmaplist):
        for i in range(0, self.size):
            self.ref.append(dexmaplist[0x2004].getreference(self.entries[i]))

    def printf(self):
        print ("size: ", self.size)

# alignment: 4bytes
class AnnotationsetrefList:
    def __init__(self):
        self.start = 0
        self.size = 0
        self.list = []  # annotaions_off, offset of annotation_set_item
        self.ref = []
        self.len = 0

    def dump(self, addr):
        self.start = addr
        self.size = getDword(addr)
        self.len = 4 + 4 * self.size
        for i in range(0, self.size):
            self.list.append(getDword(addr + 4 + 4 * i))

    def copytofile(self, file):
        file.write(struct.pack("I", self.size))
        for i in range(0, self.size):
            if self.ref[i] is not None:
                file.write(struct.pack("I", self.ref[i].start))
            else:
                file.write(struct.pack("I", 0))

    def makeoffset(self, off):
        align = off % 4
        if align != 0:
            off += (4 - align)
        self.start = off
        self.len = 4 + 4 * self.size
        return off + self.len

    def getreference(self, dexmaplist):
        for i in range(0, self.size):
            self.ref.append(dexmaplist[0x1003].getreference(self.list[i]))

    def printf(self):
        print ("size: ", self.size)

# alignment:none
class ClassdataItem:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.static_field_size = 0
        self.instance_fields_size = 0
        self.direct_methods_size = 0
        self.virtual_methods_size = 0
        self.static_fields = []
        self.instance_fields = []
        self.direct_methods = []
        self.virtual_methods = []

    def dump(self, addr, code_table):
        self.start = addr
        self.static_field_size, length = readunsignedleb128(addr)
        self.len += length
        self.instance_fields_size, length = readunsignedleb128(addr + self.len)
        self.len += length
        self.direct_methods_size, length = readunsignedleb128(addr + self.len)
        self.len += length
        self.virtual_methods_size, length = readunsignedleb128(addr + self.len)
        self.len += length
        print("class item", self.static_field_size, self.instance_fields_size, self.direct_methods_size, self.virtual_methods_size)
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
            method.dump(addr + self.len, code_table)
            self.len += method.len
            self.direct_methods.append(method)
        for i in range(0, self.virtual_methods_size):
            method = Encodedmethod()
            method.dump(addr + self.len, code_table)
            self.len += method.len
            self.virtual_methods.append(method)

    def copytofile(self, file):
        file.seek(self.start)
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

    # besides adding refenrence, also need to set the correct index
    def getreference(self, dexmaplist):
        last = 0
        for i in range(0, self.static_field_size):
            self.static_fields[i].field_idx = last + self.static_fields[i].field_idx_diff
            last = self.static_fields[i].field_idx
        last = 0
        for i in range(0, self.instance_fields_size):
            self.instance_fields[i].field_idx = last + self.instance_fields[i].field_idx_diff
            last = self.instance_fields[i].field_idx
        last = 0
        for i in range(0, self.direct_methods_size):
            self.direct_methods[i].getreference(dexmaplist)
            self.direct_methods[i].method_idx = last + self.direct_methods[i].method_idx_diff
            last = self.direct_methods[i].method_idx
        last = 0
        for i in range(0, self.virtual_methods_size):
            self.virtual_methods[i].getreference(dexmaplist)
            self.virtual_methods[i].method_idx = last + self.virtual_methods[i].method_idx_diff
            last = self.virtual_methods[i].method_idx

    def makeoffset(self, off):
        self.start = off
        off += unsignedleb128forlen(self.static_field_size)
        off += unsignedleb128forlen(self.instance_fields_size)
        off += unsignedleb128forlen(self.direct_methods_size)
        off += unsignedleb128forlen(self.virtual_methods_size)
        for i in range(0, self.static_field_size):
            off = self.static_fields[i].makeoffset(off)
        for i in range(0, self.instance_fields_size):
            off = self.instance_fields[i].makeoffset(off)
        for i in range(0, self.direct_methods_size):
            off = self.direct_methods[i].makeoffset(off)
        for i in range(0, self.virtual_methods_size):
            off = self.virtual_methods[i].makeoffset(off)
        self.len = off - self.start
        return off

    def printf(self):
        print ("static field size: ", self.static_field_size)
        print ("instance fields size: ", self.instance_fields_size)
        print ("direct methods size: ", self.direct_methods_size)
        print ("virtual methods size: ", self.virtual_methods_size)
        for i in range(0, self.static_field_size):
            self.static_fields[i].printf()
        for i in range(0, self.instance_fields_size):
            self.instance_fields[i].printf()
        for i in range(0, self.direct_methods_size):
            self.direct_methods[i].printf()
        for i in range(0, self.virtual_methods_size):
            self.virtual_methods[i].printf()

class Encodedfield:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.field_idx_diff = 0
        self.access_flags = 0
        self.field_idx = 0      # need to set later

    def dump(self, addr):
        self.start = addr
        self.field_idx_diff, length = readunsignedleb128(addr)
        self.len += length
        self.access_flags, length = readunsignedleb128(addr + self.len)
        self.len += length

    def __lt__(self, other):    # for sort
        return self.field_idx_diff < other.field_idx_diff

    def copytofile(self, file):
        writeunsignedleb128(self.field_idx_diff, file)
        writeunsignedleb128(self.access_flags, file)

    def makeoffset(self, off):
        self.start = off
        self.len += unsignedleb128forlen(self.field_idx_diff)
        self.len += unsignedleb128forlen(self.access_flags)
        return off + self.len

    def printf(self):
        print ("diff: ", self.field_idx_diff)
        print ("access: ", self.access_flags)

class Encodedmethod:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.method_idx_diff = 0
        self.access_flags = 0
        self.code_off = 0
        self.method_idx = 0
        self.coderef = None
        self.modified = 0   # if set this var, means that code_off will moodified to zero

    def dump(self, addr, code_table):
        self.start = addr
        self.method_idx_diff, length = readunsignedleb128(addr)
        self.len += length
        self.access_flags, length = readunsignedleb128(addr + self.len)
        self.len += length
        self.code_off, length = readunsignedleb128(addr + self.len)
        self.len += length
        if self.code_off != 0:
            self.coderef = CodeItem()
            self.coderef.dump(int(self.code_off + baseAddr) & 0xFFFFFFFF)
            code_table.append(self.coderef)

    def copytofile(self, file):
        writeunsignedleb128(self.method_idx_diff, file)
        writeunsignedleb128(self.access_flags, file)
        if self.modified == 1:
            writeunsignedleb128(0, file)
        elif self.coderef is not None:
            writeunsignedleb128(self.coderef.start, file)
        else:
            writeunsignedleb128(0, file)

    def makeoffset(self, off):
        self.start = off
        self.len += unsignedleb128forlen(self.method_idx_diff)
        self.len += unsignedleb128forlen(self.access_flags)
        if self.modified == 1:
            self.len += unsignedleb128forlen(0)
        elif self.coderef is not None:
            self.len += unsignedleb128forlen(self.coderef.start)
        else:
            self.len += unsignedleb128forlen(0)
        return off + self.len

    def getreference(self, dexmaplist):
        self.coderef = dexmaplist[0x2001].getreference(self.code_off)

    def printf(self):
        print ("method_idx_diff: ", self.method_idx_diff)
        print("method idx:", self.method_idx)
        print ("access: ", self.access_flags)
        print ("code off: ", self.code_off)

# alignment: 4bytes
class CodeItem:
    def __init__(self):
        self.start = 0
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
        self.start = addr
        self.register_size = getWord(addr)
        self.ins_size = getWord(addr + 2)
        self.outs_size = getWord(addr + 4)
        self.tries_size = getWord(addr + 6)
        self.debug_info_off = getDword(addr + 8)
        self.insns_size = getDword(addr + 12)
        self.len += 16
        print(self.start, self.register_size, self.ins_size, self.outs_size, self.tries_size, self.debug_info_off, self.insns_size)
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
        align = self.len % 4
        if align != 0:
            self.len += (4 - align)

    def copytofile(self, file):
        file.seek(self.start, 0)
        file.write(struct.pack("H", self.register_size))
        file.write(struct.pack("H", self.ins_size))
        file.write(struct.pack("H", self.outs_size))
        file.write(struct.pack("H", self.tries_size))
        if self.debugRef is not None:
            file.write(struct.pack("I", self.debugRef.start))
        else:
            file.write(struct.pack("I", 0))
        file.write(struct.pack("I", self.insns_size))
        for i in range(0, self.insns_size):
            file.write(struct.pack("H", self.insns[i]))
        if self.tries_size != 0 and self.insns_size % 2 == 1:
            file.write(struct.pack("H", self.padding))
        for i in range(0, self.tries_size):
            self.tries[i].copytofile(file)
        if self.tries_size != 0:
            self.handler.copytofile(file)
        align = file.tell() % 4    # for alignment
        if align != 0:
            for i in range(0, 4-align):
                file.write(struct.pack("B", 0))
        # print("code item addr:", file.tell())

    def makeoffset(self, off):
        align = off % 4
        if align != 0:
            off += (4 - align)
        self.start = off
        off += (4 * 2 + 2 * 4)  # 4 ushort and 2 uint
        off += (2 * self.insns_size)
        if self.tries_size != 0 and self.insns_size % 2 == 1:   # for padding
            off += 2
        for i in range(0, self.tries_size):
            off = self.tries[i].makeoffset(off)
        if self.tries_size != 0:
            off = self.handler.makeoffset(off)
        self.len = off - self.start
        return off

    def getreference(self, dexmaplist):
        self.debugRef = dexmaplist[0x2003].getreference(self.debug_info_off)

    def printf(self):
        print("registers_size:", self.register_size)
        print("ins_size, outs_size, tries_size:", self.ins_size, self.outs_size, self.tries_size)
        print("debug info of:", self.debug_info_off)
        print("insn_size:", self.insns_size)
        for i in range(0, self.insns_size):
            print(self.insns[i])
        # tmp = Instruction.InstructionSet(self.insns)
        # tmp.printf()

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

    def copytofile(self, file):
        file.write(struct.pack("I", self.start_addr))
        file.write(struct.pack("H", self.insn_count))
        file.write(struct.pack("H", self.handler_off))

    def makeoffset(self, off):
        self.start = off
        self.len = 4 + 2 + 2
        return off + self.len

    def printf(self):
        print ("start_Addr: ", self.start_addr)
        print ("insn_count: ", self.insn_count)
        print ("handler_off: ", self.handler_off)
        print ()

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

    def copytofile(self, file):
        file.seek(self.start, 0)
        writeunsignedleb128(self.size, file)
        for i in range(0, self.size):
            self.list[i].copytofile(file)

    def makeoffset(self, off):
        self.start = off
        off += unsignedleb128forlen(self.size)
        for i in range(0, self.size):
            off = self.list[i].makeoffset(off)
        return off

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

    def copytofile(self, file):
        writesignedleb128(self.size, file)
        for i in range(0, abs(self.size)):
            self.handlers[i].copytofile(file)
        if self.size <= 0:
            writeunsignedleb128(self.catch_all_addr, file)

    def makeoffset(self, off):
        self.start = off
        off += signedleb128forlen(self.size)
        for i in range(0, abs(self.size)):
            off = self.handlers[i].makeoffset(off)
        if self.size <= 0:
            off += unsignedleb128forlen(self.catch_all_addr)
        self.len = off - self.start
        return off

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

    def copytofile(self, file):
        writeunsignedleb128(self.type_idx, file)
        writeunsignedleb128(self.addr, file)

    def makeoffset(self, off):
        off += unsignedleb128forlen(self.type_idx)
        off += unsignedleb128forlen(self.addr)
        return off

    def printf(self):
        print ("type idx: ", self.type_idx)
        print ("addr: ", self.addr)
        print ()

class StringData:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.size = 0
        self.str = []

    def dump(self, addr):
        self.start = addr
        self.size, length = readunsignedleb128(addr)
        self.len += length
        while 1:
            onebyte = getByte(addr + self.len)
            self.len += 1
            if onebyte == 0:
                break
            self.str.append(onebyte)

    def copytofile(self, file):
        writeunsignedleb128(self.size, file)
        for i in range(0, len(self.str)):
            file.write(struct.pack("B", self.str[i]))
        file.write(struct.pack("B", 0))

    def makeoffset(self, off):
        self.start = off
        self.len = len(self.str) + unsignedleb128forlen(self.size)
        return off + self.len + 1   # 1 byte for '\0'

    def modify(self, str):
        self.size = len(str)
        self.str = bytearray(str)

    def printf(self):
        print (getstr(self.str))

# alignment: none
class DebugInfo:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.line_start = 0
        self.parameters_size = 0
        self.parameter_names = []
        self.debug = []

    def dump(self, addr):
        self.start = addr
        self.line_start, length = readunsignedleb128(addr)
        self.len += length
        self.parameters_size, length = readunsignedleb128(addr + self.len)
        self.len += length
        for i in range(0, self.parameters_size):
            num, length = readunsignedleb128p1(addr + self.len)
            self.len += length
            self.parameter_names.append(num)
        while 1:
            onebyte = getByte(addr + self.len)
            self.len += 1
            self.debug.append(onebyte)
            if onebyte == 0:
                break
            elif onebyte == 1 or onebyte == 5 or onebyte == 6:
                num, length = readunsignedleb128(addr + self.len)
                self.len += length
                self.debug.append(num)
            elif onebyte == 2:
                num, length = readsignedleb128(addr + self.len)
                self.len += length
                self.debug.append(num)
            elif onebyte == 3:
                num, length = readunsignedleb128(addr + self.len)
                self.len += length
                self.debug.append(num)
                num, length = readunsignedleb128p1(addr + self.len)
                self.len += length
                self.debug.append(num)
                num, length = readunsignedleb128p1(addr + self.len)
                self.len += length
                self.debug.append(num)
            elif onebyte == 4:
                num, length = readunsignedleb128(addr + self.len)
                self.len += length
                self.debug.append(num)
                num, length = readunsignedleb128p1(addr + self.len)
                self.len += length
                self.debug.append(num)
                num, length = readunsignedleb128p1(addr + self.len)
                self.len += length
                self.debug.append(num)
                num, length = readunsignedleb128p1(addr + self.len)
                self.len += length
                self.debug.append(num)
            elif onebyte == 9:
                num, length = readunsignedleb128p1(addr + self.len)
                self.len += length
                self.debug.append(num)

    def adddebugitem(self, linestart, paramsize, names_list, debug_list):
        self.line_start = linestart
        self.parameters_size = paramsize
        self.parameter_names = names_list
        self.debug = debug_list

    def copytofile(self, file):
        file.seek(self.start, 0)
        writeunsignedleb128(self.line_start, file)
        writeunsignedleb128(self.parameters_size, file)
        for i in range(0, self.parameters_size):
            # print(self.parameter_names[i])
            # if i == self.parameters_size-1:
                # writeunsignedleb128p1alignshort(self.parameter_names[i], file)
            # else:
            writeunsignedleb128p1(self.parameter_names[i], file)
        index = 0
        while 1:
            onebyte = self.debug[index]
            file.write(struct.pack("B", onebyte))
            index += 1
            if onebyte == 0:
                break
            elif onebyte == 1:
                writeunsignedleb128(self.debug[index], file)
                index += 1
            elif onebyte == 2:
                writesignedleb128(self.debug[index], file)
                index += 1
            elif onebyte == 3:
                writeunsignedleb128(self.debug[index], file)
                writeunsignedleb128p1(self.debug[index+1], file)
                writeunsignedleb128p1(self.debug[index+2], file)
                index += 3
            elif onebyte == 4:
                writeunsignedleb128(self.debug[index], file)
                writeunsignedleb128p1(self.debug[index+1], file)
                writeunsignedleb128p1(self.debug[index+2], file)
                writeunsignedleb128p1(self.debug[index+3], file)
                index += 4
            elif onebyte == 5:
                writeunsignedleb128(self.debug[index], file)
                index += 1
            elif onebyte == 6:
                writeunsignedleb128(self.debug[index], file)
                index += 1
            elif onebyte == 9:
                writeunsignedleb128p1(self.debug[index], file)
                index += 1

    def printf(self):
        print(self.line_start, self.parameters_size)

    def makeoffset(self, off):
        self.start = off
        off += unsignedleb128forlen(self.line_start)
        off += unsignedleb128forlen(self.parameters_size)
        for i in range(0, self.parameters_size):
            off += unsignedleb128p1forlen(self.parameter_names[i])
        index = 0
        while 1:
            onebyte = self.debug[index]
            off += 1
            index += 1
            if onebyte == 0:
                break
            elif onebyte == 1:
                off += unsignedleb128forlen(self.debug[index])
                index += 1
            elif onebyte == 2:
                off += signedleb128forlen(self.debug[index])
                index += 1
            elif onebyte == 3:
                off += unsignedleb128forlen(self.debug[index])
                off += unsignedleb128p1forlen(self.debug[index+1])
                off += unsignedleb128p1forlen(self.debug[index+2])
                index += 3
            elif onebyte == 4:
                off += unsignedleb128forlen(self.debug[index])
                off += unsignedleb128p1forlen(self.debug[index+1])
                off += unsignedleb128p1forlen(self.debug[index+2])
                off += unsignedleb128p1forlen(self.debug[index+3])
                index += 4
            elif onebyte == 5:
                off += unsignedleb128forlen(self.debug[index])
                index += 1
            elif onebyte == 6:
                off += unsignedleb128forlen(self.debug[index])
                index += 1
            elif onebyte == 9:
                off += unsignedleb128p1forlen(self.debug[index])
                index += 1
        self.len = off - self.start
        return off

# alignment: none
class AnnotationItem:
    Visibity = {0: 'VISIBITITY_BUILD', 1: 'VISIBILITY_RUNTIME', 2: 'VISIBILITY_SYSTEM'}

    def __init__(self):
        self.start = 0
        self.len = 0
        self.visibility = 0
        self.annotation = EncodedAnnotation()

    def dump(self, addr):
        self.start = addr
        self.visibility = getByte(addr)  # infile
        self.annotation.dump(addr + 1)
        self.len = self.annotation.len + 1

    def copytofile(self, file):
        file.write(struct.pack("B", self.visibility))
        self.annotation.copytofile(file)

    def makeoffset(self, off):
        self.start = off
        off += 1
        off = self.annotation.makeoffset(off)
        self.len = off - self.start
        return off


class EncodedAnnotation:
    def __init__(self):
        self.len = 0
        self.type_idx = 0
        self.size = 0
        self.elements = []

    def dump(self, addr):
        self.type_idx, length = readunsignedleb128(addr)
        self.len += length
        self.size, length = readunsignedleb128(addr + self.len)
        self.len += length
        self.elements = []  # annotation_element[size]
        for i in range(0, self.size):
            element = AnnotationElement()
            element.dump(addr + self.len)
            self.len += element.len
            self.elements.append(element)

    def copytofile(self, file):
        writeunsignedleb128(self.type_idx, file)
        writeunsignedleb128(self.size, file)
        for i in range(0, self.size):
            self.elements[i].copytofile(file)

    def makeoffset(self, off):
        off += unsignedleb128forlen(self.type_idx)
        off += unsignedleb128forlen(self.size)
        for i in range(0, self.size):
            off = self.elements[i].makeoffset(off)
        return off


class AnnotationElement:
    def __init__(self):
        self.len = 0
        self.name_idx = 0
        self.value = EncodedValue()

    def dump(self, addr):
        self.name_idx, length = readunsignedleb128(addr)
        self.len += length
        self.value.dump(addr + self.len)
        self.len += self.value.len

    def copytofile(self, file):
        writeunsignedleb128(self.name_idx, file)
        self.value.copytofile(file)

    def makeoffset(self, off):
        off += unsignedleb128forlen(self.name_idx)
        off = self.value.makeoffset(off)
        return off


class EncodedValue:

    def __init__(self):
        self.len = 0
        self.onebyte = 0
        self.type = 0
        self.arg = 0
        self.value = []

    def dump(self, addr):
        self.onebyte = getByte(addr)
        self.type = self.onebyte & 0x1F
        self.arg = (self.onebyte >> 5) & 0x7
        if self.type == 0x00:
            # print 'here 0x00 VALUE_BYTE in class : '  + str(curClass_idx)
            if self.arg != 0:
                print ("[-] Ca ,get error in VALUE_BYTE")
            self.value.append(getByte(addr + 1))
            self.len = 2
        elif self.type == 0x02:
            # print 'here 0x02 VALUE_SHORT in class : '  + str(curClass_idx)
            if self.arg >= 2:
                print ("[-] Ca ,get error in VALUE_SHORT at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x03:
            # print 'here 0x03 VALUE_CHAR in class : '  + str(curClass_idx)
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x04:
            # print 'here 0x04 VALUE_INT in class : '  + str(curClass_idx)
            if self.arg >= 4:
                print ("[-] Ca ,get error in VALUE_INT at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x06:
            # print 'here 0x06 VALUE_LONG in class : '  + str(curClass_idx)
            if self.arg >= 8:
                print ("[-] Ca ,get error in VALUE_LONG at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x10:
            # print 'here 0x10 VALUE_FLOAT in class : '  + str(curClass_idx)
            if self.arg >= 4:
                print ("[-] Ca ,get error in VALUE_FLOAT at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x11:
            # print 'here 0x11 VALUE_DOUBLE in class : '  + str(curClass_idx)
            if self.arg >= 8:
                print ("[-] Ca ,get error in VALUE_DOUBLE at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x17:
            # print 'here 0x17 VALUE_STRING in class : '  + str(curClass_idx)
            if self.arg >= 4:
                print ("[-] Ca ,get error in VALUE_STRING at class : ", hex(addr))
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x18:
            # print 'here 0x18 VALUE_TYPE in class : '  + str(curClass_idx)
            if self.arg >= 4:
                print ("[-] Ca ,get error in VALUE_TYPE at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x19:
            # print 'here 0x19 VALUE_FIELD in class : '  + str(curClass_idx)
            if self.arg >= 4:
                print ("[-] Ca ,get error in VALUE_FIELD at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x1a:
            # print 'here 0x1a VALUE_METHOD in class : '  + str(curClass_idx)
            if self.arg >= 4:
                print ("[-] Ca ,get error in VALUE_METHOD at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x1b:
            # print 'here 0x1b VALUE_ENUM in class : '  + str(curClass_idx)
            if self.arg >= 4:
                print ("[-] Ca ,get error in VALUE_ENUM at class : ")
            for i in range(0, self.arg+1):
                self.value.append(getByte(addr + 1 + i))
            self.len = self.arg + 2
        elif self.type == 0x1c:
            # print 'here 0x1c VALUE_ARRAY in class : '  + str(curClass_idx)
            if self.arg != 0x00:
                print ("[-] Ca ,get error in VALUE_ARRAY")
            array = EncodedArray()
            array.dump(addr + 1)
            self.len = array.len + 1
            self.value.append(array)
        elif self.type == 0x1d:
            # print 'here 0x1d VALUE_ANNOTATION in class : '  + str(curClass_idx)
            anno = EncodedAnnotation()
            anno.dump(addr + 1)
            self.len = anno.len + 1
            self.value.append(anno)
        else:
            self.len = 1
            # if case(0x1e):
                # print 'here 0x1e VALUE_NULL in class : '  + str(curClass_idx)
            #     break
            # if case(0x1f):
                # print 'here 0x1f VALUE_BOOLEAN in class : '  + str(curClass_idx)
            #     break

    def copytofile(self, file):
        file.write(struct.pack("B", self.onebyte))
        if self.type <= 0x1b:
            for i in range(0, self.arg+1):
                file.write(struct.pack("B", self.value[i]))
        elif self.type == 0x1c:
            self.value[0].copytofile(file)
        elif self.type == 0x1d:
            self.value[0].copytofile(file)

    def makeoffset(self, off):
        off += 1
        if self.type <= 0x1b:
            off += self.arg+1
        elif self.type == 0x1c:
            off = self.value[0].makeoffset(off)
        elif self.type == 0x1d:
            off = self.value[0].makeoffset(off)
        return off

    def printf(self):
        print("encoded value :", self.type, self.arg)

class EncodedArray:
    def __init__(self):
        self.size = 0
        self.len = 0
        self.values = []

    def dump(self, addr):
        self.size, length = readunsignedleb128(addr)
        self.len += length
        for i in range(0, self.size):
            value = EncodedValue()
            value.dump(addr + self.len)
            self.len += value.len
            self.values.append(value)

    def copytofile(self, file):
        writeunsignedleb128(self.size, file)
        for i in range(0, self.size):
            self.values[i].copytofile(file)

    def makeoffset(self, off):
        off += unsignedleb128forlen(self.size)
        for i in range(0, self.size):
            off = self.values[i].makeoffset(off)
        return off

    def printf(self):
        print("encoded array size", self.size)

# alignment: none
class EncodedArrayItem:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.value = EncodedArray()

    def dump(self, addr):
        self.start = addr
        self.len = 0
        self.value.dump(addr)
        self.len = self.value.len

    def copytofile(self, file):
        self.value.copytofile(file)

    def makeoffset(self, off):
        # if self.start == 1096008:
        self.start = off
        off = self.value.makeoffset(off)
        self.len = off - self.start
        return off

    def printf(self):
        print("None for EncodedArrayItem by now")

# alignment: 4 bytes
class AnnotationsDirItem:
    def __init__(self):
        self.start = 0
        self.len = 0
        self.class_annotations_off = 0
        self.fields_size = 0
        self.annotated_methods_size = 0
        self.annotate_parameters_size = 0
        self.field_annotations = []  # field_annotation[size]
        self.method_annotations = []
        self.parameter_annotations = []
        self.class_annotations_ref = None

    def dump(self, addr):
        self.start = addr
        self.class_annotations_off = getDword(addr)   # in file
        self.fields_size = getDword(addr + 4)   # in file
        self.annotated_methods_size = getDword(addr + 8)   # in file
        self.annotate_parameters_size = getDword(addr + 12)   # in file
        self.len = 16
        for i in range(0, self.fields_size):
            field = FieldAnnotation()
            field.dump(addr + self.len + 8 * i)
            self.field_annotations.append(field)
        self.len += 8 * self.fields_size
        for i in range(0, self.annotated_methods_size):
            method = MethodAnnotation()
            method.dump(addr + self.len + 8 * i)
            self.method_annotations.append(method)
        self.len += 8 * self.annotated_methods_size
        for i in range(0, self.annotate_parameters_size):
            param = ParamterAnnotation()
            param.dump(addr + 8 * i)
            self.parameter_annotations.append(param)
        self.len += 8 * self.annotate_parameters_size

    def copytofile(self, file):
        if self.class_annotations_ref is not None:
            file.write(struct.pack("I", self.class_annotations_ref.start))
        else:
            file.write(struct.pack("I", self.class_annotations_off))
        file.write(struct.pack("I", self.fields_size))
        file.write(struct.pack("I", self.annotated_methods_size))
        file.write(struct.pack("I", self.annotate_parameters_size))
        for i in range(0, self.fields_size):
            self.field_annotations[i].copytofile(file)
        for i in range(0, self.annotated_methods_size):
            self.method_annotations[i].copytofile(file)
        for i in range(0, self.annotate_parameters_size):
            self.parameter_annotations[i].copytofile(file)

    def makeoffset(self, off):
        self.start = off
        off += 4 * 4
        for i in range(0, self.fields_size):
            off = self.field_annotations[i].makeoffset(off)
        for i in range(0, self.annotated_methods_size):
            off = self.method_annotations[i].makeoffset(off)
        for i in range(0, self.annotate_parameters_size):
            off = self.parameter_annotations[i].makeoffset(off)
        self.len = off - self.start
        return off

    def getreference(self, dexmaplist):
        self.class_annotations_ref = dexmaplist[0x1003].getreference(self.class_annotations_off)
        for i in range(0, self.fields_size):
            self.field_annotations[i].getreference(dexmaplist)
        for i in range(0, self.annotated_methods_size):
            self.method_annotations[i].getreference(dexmaplist)
        for i in range(0, self.annotate_parameters_size):
            self.parameter_annotations[i].getreference(dexmaplist)

    def printf(self):
        print("None for AnnotationDirItem by now")

class FieldAnnotation:
    def __init__(self):
        self.field_idx = 0
        self.annotations_off = 0
        self.annotations_off_ref = None

    def dump(self, addr):
        self.field_idx = getDword(addr)   # in file
        self.annotations_off = getDword(addr + 4)   # in file, offset of annotation_set_item
        self.annotations_off_ref = None

    def copytofile(self, file):
        file.write(struct.pack("I", self.field_idx))
        file.write(struct.pack("I", self.annotations_off_ref.start))

    def makeoffset(self, off):
        off += 4 * 2
        return off

    def getreference(self, dexmaplist):
        self.annotations_off_ref = dexmaplist[0x1003].getreference(self.annotations_off)

class MethodAnnotation:
    def __init__(self):
        self.method_idx = 0
        self.annotations_off = 0
        self.annotations_off_ref = None

    def dump(self, addr):
        self.method_idx = getDword(addr)   # in file
        self.annotations_off = getDword(addr + 4)   # in file
        self.annotations_off_ref = None

    def copytofile(self, file):
        file.write(struct.pack("I", self.method_idx))
        file.write(struct.pack("I", self.annotations_off_ref.start))

    def makeoffset(self, off):
        off += 4 * 2
        return off

    def getreference(self, dexmaplist):
        self.annotations_off_ref = dexmaplist[0x1003].getreference(self.annotations_off)

class ParamterAnnotation:
    def __init__(self):
        self.method_idx = 0
        self.annotations_off = 0
        self.annotations_off_ref = None

    def dump(self, addr):
        self.method_idx = getDword(addr)   # in file
        self.annotations_off = getDword(addr + 4)   # in file. offset of "annotation_set_ref_list"
        self.annotations_off_ref = None

    def copytofile(self, file):
        file.write(struct.pack("I", self.method_idx))
        if self.annotations_off_ref is not None:
            file.write(struct.pack("I", self.annotations_off_ref.start))
        else:
            file.write(struct.pack("I", 0))

    def makeoffset(self, off):
        off += 4 * 2
        return off

    def getreference(self, dexmaplist):
        self.annotations_off_ref = dexmaplist[0x1002].getreference(self.annotations_off)

addr = 1558176632
print(hex(addr))
cookie = DexorJar()
cookie.dump(addr)
cookie.printf()
if cookie.isDex == 0:
    jarfile = JarFile()
    jarfile.dump(cookie.pJarFile)
    jarfile.printf()
    dvmaddr = jarfile.pDvmDex
else:
    print("not support yet")
dvmDex = DvmDex()
dvmDex.dump(dvmaddr)
dvmDex.printf()
dexfile = DexFile()
dexfile.dump(dvmDex.pDexFile)
print("begin copy to file:")
dexfile.copytofile("dump.dex")


