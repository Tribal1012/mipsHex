# mips_asm_set.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

class MIPS_Asm_Set(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Set, self).__init__(addr)

	def do_sltu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sltu".format(hex(self.addr), self.ins), self.ins == 'sltu')

		o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + o_reg.get_register(self.opr3.value) + ')? True:False')

		return None, None

	def do_sltiu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sltiu".format(hex(self.addr), self.ins), self.ins == 'sltiu')
		check_assert("[-] Check opr3 type, current({0}) : {1} != {2}".format(self.addr, self.opr3.type, asm_type['Imm']), self.opr3.type == asm_type['Imm'])

		o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + self.opr3.value + ')? True:False')

		return None, None