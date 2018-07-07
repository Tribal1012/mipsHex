# mips_asm_bits.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(bits operation)
class MIPS_Asm_Bits(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Bits, self).__init__(addr)

	# and instruction
	def do_and(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != and".format(hex(self.addr), self.ins), self.ins == 'and')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' & ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' & ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined and opr3 type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='|')
		
		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' & ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined and opr2 type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='|')

		else:
			error("[-] address({0}), Not defined and".format(hex(self.addr)))

		return comment, None

	# andi instruction
	def do_andi(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != andi".format(hex(self.addr), self.ins), self.ins == 'andi')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' & ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' & ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined andi opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='&')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' & ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined and opr2 type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='&')

		else:
			error("[-] address({0}), Not defined andi".format(hex(self.addr)))

		return comment, None

	# or instruction
	def do_or(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != or".format(hex(self.addr), self.ins), self.ins == 'or')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' | ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' | ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined or".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='|')
		
		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' | ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined or opr2 type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='|')

		else:
			error("[-] address({0}), Not defined or".format(hex(self.addr)))

		return comment, None
		
	# ori instruction
	def do_ori(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != ori".format(hex(self.addr), self.ins), self.ins == 'ori')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' & ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' & ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined ori opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='&')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' & ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined ori opr2 type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='&')

		else:
			error("[-] address({0}), Not defined ori".format(hex(self.addr)))

		return comment, None

	# xor instruction
	def do_xor(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != xor".format(hex(self.addr), self.ins), self.ins == 'xor')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' ^ ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' ^ ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined xor".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='|')
		
		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' ^ ' + self.opr2.value + ')')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='|')

		else:
			error("[-] address({0}), Not defined xor".format(hex(self.addr)))

		return comment, None

	# xori instruction
	def do_xori(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != xori".format(hex(self.addr), self.ins), self.ins == 'xori')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' ^ ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' ^ ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined xori opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='&')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' ^ ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined xori opr2 type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='&')

		else:
			error("[-] address({0}), Not defined xori".format(hex(self.addr)))

		return comment, None

	# negu instruction
	def do_negu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != negu".format(hex(self.addr), self.ins), self.ins == 'negu')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		if self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '- (' + self.opr2.value + ')')

		else:
			error("[-] address({0}), Not defined negu".format(hex(self.addr)))

		return comment, None

	# not instruction
	def do_not(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != not".format(hex(self.addr), self.ins), self.ins == 'not')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		if self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '~ (' + self.opr2.value + ')')

		else:
			error("[-] address({0}), Not defined not".format(hex(self.addr)))

		return comment, None

	# nor instruction
	def do_nor(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != nor".format(hex(self.addr), self.ins), self.ins == 'nor')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '~ (' + o_reg.get_register(self.opr2.value) + ' | ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '~ (' + o_reg.get_register(self.opr2.value) + ' | ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined nor".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='|')
		
		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '~ (' + o_reg.get_register(self.opr1.value) + ' | ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined nor opr2 type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='|')

		else:
			error("[-] address({0}), Not defined nor".format(hex(self.addr)))

		return comment, None