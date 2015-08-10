__author__ = 'CwT'

from idaapi import *
from idautils import *
from idc import *

def getDword(addr):
    return Dword(addr)

def getByte(addr):
    return Byte(addr)

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

addr = 1461238144
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


