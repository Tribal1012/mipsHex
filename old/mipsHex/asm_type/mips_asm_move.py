# mips_asm_move.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(move the value between registers)
class MIPS_Asm_Move(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Move, self).__init__(addr)

	# move data instruction
	def do_move(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != move".format(hex(self.addr), self.ins), self.ins == 'move')
		if o_reg.isargument(self.opr2.value):
			o_func.set_argument(self.opr2.value.replace('$', ''))
			o_reg.set_register(self.opr1.value, self.opr2.value)

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value)
		else:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr2.value))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register(self.opr2.value))

		return comment, None

	# move if not zero instruction
	def do_movn(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != movn".format(hex(self.addr), self.ins), self.ins == 'movn')

		line = o_reg.get_register(self.opr3.value)  + '? '
		line += o_reg.get_register(self.opr2.value) + ':'
		line += o_reg.get_register(self.opr1.value)

		o_reg.set_register(self.opr1.value, line)

		comment = o_func.get_comment(opr1=self.opr1.value, opr2=line)

		return comment , None

	# move if zero instruction
	def do_movz(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != movz".format(hex(self.addr), self.ins), self.ins == 'movz')

		line = '!' + o_reg.get_register(self.opr3.value)  + '? '
		line += o_reg.get_register(self.opr2.value) + ':'
		line += o_reg.get_register(self.opr1.value)

		o_reg.set_register(self.opr1.value, line)

		comment = o_func.get_comment(opr1=self.opr1.value, opr2=line)

		return comment , None

	# move from high instruction
	def do_mfhi(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != mfhi".format(hex(self.addr), self.ins), self.ins == 'mfhi')

		o_reg.set_register(self.opr1.value, o_reg.get_register('$hi'))

		comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register('$hi'))

		return comment , None

	# move from low instruction
	def do_mflo(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != mflo".format(hex(self.addr), self.ins), self.ins == 'mflo')

		o_reg.set_register(self.opr1.value, o_reg.get_register('$lo'))

		comment = o_func.get_comment(opr1=self.opr1.value, opr2=o_reg.get_register('$lo'))

		return comment , None

	# move to high instruction
	def do_mthi(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != mthi".format(hex(self.addr), self.ins), self.ins == 'mthi')

		o_reg.set_register('$hi', o_reg.get_register(self.opr2.value))

		comment = o_func.get_comment(opr1='$hi', opr2=o_reg.get_register(self.opr2.value))

		return comment , None

	# move to low instruction
	def do_mtlo(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != mtlo".format(hex(self.addr), self.ins), self.ins == 'mtlo')

		o_reg.set_register('$lo', o_reg.get_register(self.opr2.value))

		comment = o_func.get_comment(opr1='$lo', opr2=o_reg.get_register(self.opr2.value))

		return comment , None
