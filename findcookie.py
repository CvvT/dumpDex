__author__ = 'CwT'

from idaapi import *
from idautils import *
from idc import *
import re

def getDword(addr):
    return Dword(addr)

def getByte(addr):
    return Byte(addr)

def getWord(addr):
    return Word(addr)

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
            pass
            # print("it's a dex file, addr: ", hex(self.pRawDexFile))
        else:
            # print("it's a jar file, addr: ", hex(self.pJarFile))
            jarfile = JarFile()
            jarfile.dump(cookie.pJarFile)
            jarfile.printf()
            dvmaddr = jarfile.pDvmDex

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
        # print("DvmDex addr is :", hex(self.pDvmDex))

class RawDexFile:
    def __init__(self):
        self.pcacheFileName = 0
        self.pDvmDex = 0

    def dump(self, addr):
        self.pcacheFileName = getDword(addr)
        self.pDvmDex = getDword(addr+4)

    def printf(self):
        str = ""
        baseaddr = self.pcacheFileName
        if baseaddr == 0:
            print "cache file name is null"
            return
        one = getByte(baseaddr)
        while one != 0:
            str += chr(one)
            baseaddr += 1
            one = getByte(baseaddr)
        print("cache file name is : ", str)
        # print("DvmDex addr is :", hex(self.pDvmDex))

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
        # print("header addr is: ", hex(self.pHeader))

experiment = True
if experiment:
    gDvm = 0
    offset = 0
    for i in range(10):
        insn = GetDisasm(here()+i*2)
        match = re.search(r'PC[\s]*;[\s]*dword_(?P<addr>[0-9A-Z]+)', insn)
        if match is not None:
            address = "0x" + match.group('addr')
            gDvm = Dword(int(address, 16))
        match = re.search(r'[R[\d]+,#(?P<off>0x[\dA-F]+)]', insn)
        if match is not None:
            offset = match.group('off')
            offset = int(offset, 16)
    target = gDvm + offset
else:
    target = int(0x40DDB654)  # find it in dvminternalnativeshutdown--->dvmHashTableFree
print "target:", hex(target)
userDex = getDword(target)
size = getDword(userDex)
entry = getDword(userDex+12)
print "Size:", size
print "Entry:", hex(entry)
for i in range(size):
    hash = getDword(entry+8*i)
    item = getDword(entry+8*i+4)
    if hash == item and hash != 0:
        cookie = DexorJar()
        cookie.dump(hash)
        cookie.printf()
        if cookie.isDex == 0:
            jarfile = JarFile()
            jarfile.dump(cookie.pJarFile)
            jarfile.printf()
            dvmaddr = jarfile.pDvmDex
        else:
            rawDex = RawDexFile()
            rawDex.dump(cookie.pRawDexFile)
            rawDex.printf()
            dvmaddr = rawDex.pDvmDex
        dvmDex = DvmDex()
        dvmDex.dump(dvmaddr)
        dvmDex.printf()
