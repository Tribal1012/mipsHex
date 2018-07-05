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

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '&' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '&' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined andi opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='&')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '&' + self.opr2.value + ')')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='&')

		else:
			error("[-] address({0}), Not defined andi".format(hex(self.addr)))

		return comment, None

	# or instruction
	def do_or(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != or".format(hex(self.addr), self.ins), self.ins == 'or')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '|' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '|' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined or".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='|')
		
		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '|' + self.opr2.value + ')')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='|')

		else:
			error("[-] address({0}), Not defined or".format(hex(self.addr)))

		return comment, None
		