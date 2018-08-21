# mips_asm_bits.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(shift operation)
class MIPS_Asm_Shift(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Shift, self).__init__(addr)

	# srl shift instruction
	def do_srl(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != srl".format(hex(self.addr), self.ins), self.ins == 'srl')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ')' + ' >> ' + self.opr3.value)

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='>>')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ')' + ' >> ' + self.opr2.value)

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='>>')

		else:
			error("[-] address({0}), Not defined srl opernad type({1})".format(hex(self.addr), self.opr2.type))

		return comment, None

	# srlv shift instruction
	def do_srlv(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != srlv".format(hex(self.addr), self.ins), self.ins == 'srlv')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ')' + ' >> ' + o_reg.get_register(self.opr3.value))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='>>')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ')' + ' >> ' + o_reg.get_register(self.opr2.value))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='>>')

		else:
			error("[-] address({0}), Not defined srlv opernad type({1})".format(hex(self.addr), self.opr2.type))

		return comment, None

	# sra shift instruction
	def do_sra(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sra".format(hex(self.addr), self.ins), self.ins == 'sra')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ')' + ' >> ' + self.opr3.value)

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='>>')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ')' + ' >> ' + self.opr2.value)

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='>>')

		else:
			error("[-] address({0}), Not defined sra".format(hex(self.addr)))

		return comment, None

	# srav shift instruction
	def do_srav(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != srav".format(hex(self.addr), self.ins), self.ins == 'srav')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ')' + ' >> ' + o_reg.get_register(self.opr3.value))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='>>')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ')' + ' >> ' + o_reg.get_register(self.opr2.value))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='>>')

		else:
			error("[-] address({0}), Not defined srav".format(hex(self.addr)))

		return comment, None

	# sll shift instruction
	def do_sll(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sll".format(hex(self.addr), self.ins), self.ins == 'sll')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ')' + ' << ' + self.opr3.value)

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='<<')
		
		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ')' + ' << ' + self.opr2.value)

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='<<')
			
		else:
			error("[-] address({0}), Not defined sll".format(hex(self.addr)))

		return comment, None

	# shift left local variable instruction
	def do_sllv(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sllv".format(hex(self.addr), self.ins), self.ins == 'sllv')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ')' + ' << ' + o_reg.get_register(self.opr3.value))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='<<')
		
		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ')' + ' << ' + o_reg.get_register(self.opr2.value))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='<<')
			
		else:
			error("[-] address({0}), Not defined sllv".format(hex(self.addr)))

		return comment, None
