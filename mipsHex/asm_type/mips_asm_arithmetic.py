# mips_asm_arithmetic.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

class MIPS_Asm_Arithmetic(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Arithmetic, self).__init__(addr)

		# self.mips_asm_arithmetic = ['addiu', 'subu']
		pass

	def do_addiu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != addiu".format(hex(self.addr), self.ins), self.ins == 'addiu')

		if self.opr2.type == asm_type['Gen_Reg']:
			if self.opr3.value.find('+') != -1 and self.opr2.value == '$sp':
				new_opr = asmutils.convert_to_var(self.opr3.value + '(' + self.opr2.value + ')', o_reg)
				o_reg.set_register(self.opr1.value, new_opr)
			else:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '+' + self.opr3.value + ')')
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '+' + self.opr2.value + ')')
		else:
			error("[-] current({0}), Not defined addiu operand type".format(hex(self.addr)))

		return None, None

	def do_addu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != addu".format(hex(self.addr), self.ins), self.ins == 'addu')

		if self.opr2.type == asm_type['Gen_Reg']:
			if self.opr3 is None:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '+' + self.opr2.value + ')')
			else:
				error("[-] current({0}), Not defined addu operand3".format(hex(self.addr)))
		else:
			error("[-] current({0}), Not defined addu operand type".format(hex(self.addr)))

		return None, None

	def do_subu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != subu".format(hex(self.addr), self.ins), self.ins == 'subu')

		if self.opr2.type == asm_type['Gen_Reg']:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '-' + self.opr3.value + ')')
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '-' + self.opr2.value + ')')
		else:
			error("[-] current({0}), Not defined subu operand type".format(hex(self.addr)))

		return None, None