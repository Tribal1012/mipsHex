# mips_asm_etc.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(etc)
class MIPS_Asm_Etc(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Etc, self).__init__(addr)

	# non operation instruction
	def do_nop(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != nop".format(hex(self.addr), self.ins), self.ins == 'nop')

		return None, None

	# extract instruction
	def do_ext(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != ext".format(hex(self.addr), self.ins), self.ins == 'ext')

		# Hmm...

		return None, None

	# insert instruction
	def do_ins(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != ins".format(hex(self.addr), self.ins), self.ins == 'ins')

		# Hmm...

		return None, None
		