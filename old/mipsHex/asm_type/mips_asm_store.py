# mips_asm_store.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(store to memory)
class MIPS_Asm_Store(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Store, self).__init__(addr)

	# store byte instruction
	def do_sb(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sb".format(hex(self.addr), self.ins), self.ins == 'sb')

		c_opr2 = self.opr2.convert(o_reg)
		if asmutils.check_var_naming(c_opr2):
			c_opr2 = asmutils.convert_var_naming(c_opr2)

		line = c_opr2 + ' = ' + o_reg.get_register(self.opr1.value)
		line += ';'

		if o_func.get_local_var(c_opr2) is None and asmutils.check_var_naming(c_opr2):
			o_func.set_local_var(c_opr2, o_reg.get_register(self.opr1.value))

		return line, None

	# store half word instruction
	def do_sh(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sh".format(hex(self.addr), self.ins), self.ins == 'sh')

		c_opr2 = self.opr2.convert(o_reg)
		if asmutils.check_var_naming(c_opr2):
			c_opr2 = asmutils.convert_var_naming(c_opr2)

		line = c_opr2 + ' = ' + o_reg.get_register(self.opr1.value)
		line += ';'

		if o_func.get_local_var(c_opr2) is None and asmutils.check_var_naming(c_opr2):
			o_func.set_local_var(c_opr2, o_reg.get_register(self.opr1.value))

		return line, None

	# store word instruction
	def do_sw(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sw".format(hex(self.addr), self.ins), self.ins == 'sw')

		c_opr2 = self.opr2.convert(o_reg)
		if asmutils.check_var_naming(c_opr2):
			c_opr2 = asmutils.convert_var_naming(c_opr2)

		line = c_opr2 + ' = ' + o_reg.get_register(self.opr1.value)
		line += ';'

		if o_func.get_local_var(c_opr2) is None and asmutils.check_var_naming(c_opr2):
			o_func.set_local_var(c_opr2, o_reg.get_register(self.opr1.value))

		return line, None

	# unaligned store word instruction
	def do_usw(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != usw".format(hex(self.addr), self.ins), self.ins == 'usw')

		c_opr2 = self.opr2.convert(o_reg)
		if asmutils.check_var_naming(c_opr2):
			c_opr2 = asmutils.convert_var_naming(c_opr2)

		line = c_opr2 + ' = ' + o_reg.get_register(self.opr1.value)
		line += ';'

		if o_func.get_local_var(c_opr2) is None and asmutils.check_var_naming(c_opr2):
			o_func.set_local_var(c_opr2, o_reg.get_register(self.opr1.value))

		return line, None
		