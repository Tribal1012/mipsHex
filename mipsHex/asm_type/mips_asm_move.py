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

			line = '// ' + self.opr1.value + ' = ' + self.opr2.value
		else:
			o_reg.set_register(self.opr1.value, o_reg.get_register(self.opr2.value))

			line = '// ' + self.opr1.value + ' = ' + o_reg.get_register(self.opr2.value)

		return line, None

	# move if not zero instruction
	def do_movn(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != movn".format(hex(self.addr), self.ins), self.ins == 'movn')

		line = o_reg.get_register(self.opr3.value)  + '? '
		line += o_reg.get_register(self.opr2.value) + ':'
		line += o_reg.get_register(self.opr1.value)

		o_reg.set_register(self.opr1.value, line)

		line = '// ' + self.opr1.value + ' = ' + line

		return line, None
