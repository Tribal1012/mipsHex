# mips_asm_set.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(return condition)
class MIPS_Asm_Set(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Set, self).__init__(addr)

	# set equal instruction
	def do_seq(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != seq".format(hex(self.addr), self.ins), self.ins == 'seq')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '==' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '==' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined seq".format(hex(self.addr)))

		return comment, None

	# set not equal instruction
	def do_sne(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sne".format(hex(self.addr), self.ins), self.ins == 'sne')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '!=' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '!=' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined sne".format(hex(self.addr)))

		return comment, None

	# set not equal instruction
	def do_snei(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != snei".format(hex(self.addr), self.ins), self.ins == 'snei')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '!=' + self.opr3.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=self.opr3.value + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '!=' + self.opr2.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=self.opr2.value + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined snei".format(hex(self.addr)))

		return comment, None

	# set greater or equal instruction
	def do_sge(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sge".format(hex(self.addr), self.ins), self.ins == 'sge')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '>=' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '>=' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined sge".format(hex(self.addr)))

		return comment, None

	# set greater than instruction
	def do_sgt(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sgt".format(hex(self.addr), self.ins), self.ins == 'sgt')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '>' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '>' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined sgt".format(hex(self.addr)))

		return comment, None

	# set less or equal instruction
	def do_sle(self, o_Reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sle".format(hex(self.addr), self.ins), self.ins == 'sle')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<=' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '<=' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined sle".format(hex(self.addr)))

		return comment, None

	# set less than instruction
	def do_slt(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != slt".format(hex(self.addr), self.ins), self.ins == 'slt')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '<' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined slt".format(hex(self.addr)))

		return comment, None

	# set less than immediate instruction
	def do_slti(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != slti".format(hex(self.addr), self.ins), self.ins == 'slti')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + self.opr3.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=self.opr3.value + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '<' + self.opr2.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=self.opr2.value + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined slti".format(hex(self.addr)))

		return comment, None

	# set less than unsigned instruction
	def do_sltu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sltu".format(hex(self.addr), self.ins), self.ins == 'sltu')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + o_reg.get_register(self.opr3.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=o_reg.get_register(self.opr3.value) + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '<' + o_reg.get_register(self.opr2.value) + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=o_reg.get_register(self.opr2.value) + '? True:False', operation='<')
		
		else:
			error("[-] address({0}), Not defined sltu".format(hex(self.addr)))

		return comment, None

	# set less than unsigned immediate instruction
	def do_sltiu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sltiu".format(hex(self.addr), self.ins), self.ins == 'sltiu')

		if self.get_operand_count() == 3:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '<' + self.opr3.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value), opr3=self.opr3.value + '? True:False', operation='<')

		elif self.get_operand_count() == 2:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '<' + self.opr2.value + ')? True:False')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr1.value), opr3=self.opr2.value + '? True:False', operation='<')

		else:
			error("[-] address({0}), Not defined sltiu".format(hex(self.addr)))

		return comment, None