#!/usr/bin/python

from capstone import *
from capstone.arm import *

# arch: CS_ARCH_ARM
# MODE: CS_MODE_THUMB, CS_MODE_ARM
# CODE = "\x03\x4b\x7b\x44\x1b\x68\xd3\xf8\x1c\x03\xe2\xf7\x3d\xbd\x00\xbf\xc2\x2f\x04\x00\x03\x68\x2d\xe9\xf0\x41\x07\x46\x9e\x69\x10\x4c"
CODE = "\x03\x4b\x04\x4a\x7b\x44\x9b\x58\xd3\xf8\x30\x03\xe0\xf7\xcc\xba\x0c\x61\x04\x00\xa0\xfe\xff\xff\x2d\xe9\xf8\x43\x07\x46\x03\x68"
base = 0xb5a95b60
DEBUG = False
try:
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    insn = None
    for i in md.disasm(CODE, base):
	    if DEBUG : print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
	    if i.mnemonic.upper().startswith('LDR'):
	    	if i.reg_name(i.operands[0].value.reg) == 'r0' and i.operands[1].type == ARM_OP_MEM :
	    		insn = i
	    if i.mnemonic.upper().startswith('B'):
	    	if insn is None:
	    		print "ERROR: %s" % "offset not found"
	    	else:
	    		print "offset is :", insn.operands[1].mem.disp
	    	break

except CsError as e:
    print("ERROR: %s" %e)

