# mips_asm_set.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(return condition)
class MIPS_Asm_Set(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Set, self).__init__(addr)

	# set less than unsigned instruction
	def do_sltu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sltu".format(hex(self.addr), self.ins), self.ins == 'sltu')

		if self.get_operand_count() == 3:
			check_assert("[-] Check opr3 type, current({0}) : {1} != {2}".format(self.addr, self.opr3.type, ASM_TYPE['Imm']), self.opr3.type == ASM_TYPE['Imm'])

			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + ')? True:False', operation='<')

		elif self.get_operand_count() == 2:
			check_assert("[-] Check opr2 type, current({0}) : {1} != {2}".format(self.addr, self.opr2.type, ASM_TYPE['Imm']), self.opr2.type == ASM_TYPE['Imm'])
			
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '<' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + ')? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined sltu".format(hex(self.addr)))

		return comment, None

	# set less than unsigned immediate instruction
	def do_sltiu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sltiu".format(hex(self.addr), self.ins), self.ins == 'sltiu')

		if self.get_operand_count() == 3:
			check_assert("[-] Check opr3 type, current({0}) : {1} != {2}".format(self.addr, self.opr3.type, ASM_TYPE['Imm']), self.opr3.type == ASM_TYPE['Imm'])

			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + self.opr3.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + ')? True:False', operation='<')

		elif self.get_operand_count() == 2:
			check_assert("[-] Check opr2 type, current({0}) : {1} != {2}".format(self.addr, self.opr2.type, ASM_TYPE['Imm']), self.opr2.type == ASM_TYPE['Imm'])

			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '<' + self.opr2.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + ')? True:False', operation='<')

		else:
			error("[-] address({0}), Not defined sltiu".format(hex(self.addr)))

		return comment, None