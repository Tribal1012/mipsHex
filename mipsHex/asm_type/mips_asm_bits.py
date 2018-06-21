# mips_asm_bits.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(bits operation)
class MIPS_Asm_Bits(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Bits, self).__init__(addr)

	# andi instruction
	def do_andi(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != andi".format(hex(self.addr), self.ins), self.ins == 'andi')

		if self.opr2.type == asm_type['Gen_Reg']:
			if self.opr3.type == asm_type['Get_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '&' + o_reg.get_register(self.opr3.value) + ')')
			elif self.opr3.type == asm_type['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '&' + self.opr3.value + ')')
			else:
				error("[-] address({0}), Not defined andi opr3 type({1})".format(hex(self.addr), self.opr3.type))
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '&' + self.opr2.value + ')')
		else:
			error("[-] address({0}), Not defined andi opernad type({1})".format(hex(self.addr), self.opr2.type))

		return None, None

	# or instruction
	def do_or(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != or".format(hex(self.addr), self.ins), self.ins == 'or')

		if self.opr2.type == asm_type['Gen_Reg']:
			if self.opr3.type == asm_type['Get_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '|' + o_reg.get_register(self.opr3.value) + ')')
			elif self.opr3.type == asm_type['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '|' + self.opr3.value + ')')
			else:
				error("[-] address({0}), Not defined or opr3 type({1})".format(hex(self.addr), self.opr3.type))
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '|' + self.opr2.value + ')')
		else:
			error("[-] address({0}), Not defined or opernad type({1})".format(hex(self.addr), self.opr2.type))

		return None, None

	# srl shift instruction
	def do_srl(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != srl".format(hex(self.addr), self.ins), self.ins == 'srl')

		if self.opr2.type == asm_type['Gen_Reg']:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr2.value) + '>>' + self.opr3.value)
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr1.value) + '>>' + self.opr2.value)
		else:
			error("[-] address({0}), Not defined srl opernad type({1})".format(hex(self.addr), self.opr2.type))

		return None, None

	# sra shift instruction
	def do_sra(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sra".format(hex(self.addr), self.ins), self.ins == 'sra')

		if self.opr2.type == asm_type['Gen_Reg']:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr2.value) + '>>' + self.opr3.value)
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr1.value) + '>>' + self.opr2.value)
		else:
			error("[-] address({0}), Not defined sra opernad type({1})".format(hex(self.addr), self.opr2.type))

		return None, None

	# sll shift instruction
	def do_sll(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sll".format(hex(self.addr), self.ins), self.ins == 'sll')

		if self.opr2.type == asm_type['Gen_Reg']:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr2.value) + '<<' + self.opr3.value)
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr1.value) + '<<' + self.opr2.value)
		else:
			error("[-] address({0}), Not defined sll opernad type({1})".format(hex(self.addr), self.opr2.type))

		return None, None
		