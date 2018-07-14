# mips_asm.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from base.asm import *
from mips_asmutils import asmutils
from mips_operand import *

'''
	store mips assembly
	important : mips assmbly type, provide mips assembly utils
'''
class MIPS_Asm(Asm):
	def __init__(self, addr):
		super(MIPS_Asm, self).__init__(addr)

		if self.has_operand(self.addr, 0):
			self.opr1 = MIPS_Operand(idc.GetOpType(addr, 0), idc.GetOpnd(addr, 0))
			self.opnd_count += 1

		if self.has_operand(self.addr, 1):
			self.opr2 = MIPS_Operand(idc.GetOpType(addr, 1), idc.GetOpnd(addr, 1))
			self.opnd_count += 1

		if self.has_operand(self.addr, 2):
			self.opr3 = MIPS_Operand(idc.GetOpType(addr, 2), idc.GetOpnd(addr, 2))
			self.opnd_count += 1
