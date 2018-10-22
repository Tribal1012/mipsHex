# asm.py

import idc

from error import error, check_assert

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

	def has_operand(self, addr, idx):
		if idc.GetOpnd(addr, idx) != '':
			return True
		else:
			return False

	def get_operand_count(self):
		return self.opnd_count
		