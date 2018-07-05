# asm.py

import idc

from error import error, check_assert
from operand import Operand

from define import OPND_FEATURE, ASM_TYPE
'''
	Store assembly information from address using idapython

	__init__ : Initialize assembly information using idapython
'''
class Asm(object):
	def __init__(self, addr):
		self.addr = addr
		self.ins = idc.GetMnem(addr)
		self.opnd_count = 0
		self.opr1 = None
		self.opr2 = None
		self.opr3 = None

		if self.has_operand(self.addr, 0):
			self.opr1 = Operand(idc.GetOpType(addr, 0), idc.GetOpnd(addr, 0))
			self.opnd_count += 1

		if self.has_operand(self.addr, 1):
			self.opr2 = Operand(idc.GetOpType(addr, 1), idc.GetOpnd(addr, 1))
			self.opnd_count += 1

		if self.has_operand(self.addr, 2):
			self.opr3 = Operand(idc.GetOpType(addr, 2), idc.GetOpnd(addr, 2))
			self.opnd_count += 1

	def has_operand(self, addr, idx):
		if idc.GetOpnd(addr, idx) != '':
			return True
		else:
			return False

	def get_operand_count(self):
		return self.opnd_count
		