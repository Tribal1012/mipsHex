# mips_asm_branch.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

import idc

# instruction(conditional branch)
class MIPS_Asm_Branch(MIPS_Asm):
	def __init__(self, addr, dispatch, o_reg, o_func):
		super(MIPS_Asm_Branch, self).__init__(addr)

		self.next_addr = idc.NextHead(addr)
		self.next_result, n_addr = dispatch(self.next_addr, o_reg, o_func)
		# check_assert("[-] address({0}), dispatch error in branch".format(hex(self.next_addr)), result is None)
		check_assert("[-] address({0}), dispatch error in branch".format(hex(self.next_addr)), n_addr is None)

	# branch instruction
	def do_b(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != b".format(hex(self.addr), self.ins), self.ins == 'b')

		line = ''
		if self.next_result is not None:
			line = self.next_result
			line += '\n    '
		line += o_func.get_comment(prefix='[branch]', opr1=self.opr1.value) + '\n    '
		line += 'goto ' + self.opr1.value + ';'

		return line, self.next_addr#idc.PrevHead(idc.LocByName(self.opr1.value))

	# branch equal zero instruction
	def do_beqz(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != beqz".format(hex(self.addr), self.ins), self.ins == 'beqz')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += '!' + o_reg.get_register(self.opr1.value)
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr2.value + ';\n    ' + '}'

		return line, self.next_addr

	# branch not equal zero instruction
	def do_bnez(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != bnez".format(hex(self.addr), self.ins), self.ins == 'bnez')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += o_reg.get_register(self.opr1.value)
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr2.value + ';\n    ' + '}'

		return line, self.next_addr
	
	# branch equal instruction
	def do_beq(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != beq".format(hex(self.addr), self.ins), self.ins == 'beq')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr2.value), opr3=self.opr2.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += o_reg.get_register(self.opr1.value) + ' == ' + o_reg.get_register(self.opr2.value)
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr3.value + ';\n    ' + '}'

		return line, self.next_addr

	# branch not equal instruction
	def do_bne(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != bne".format(hex(self.addr), self.ins), self.ins == 'bne')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr2.value), opr3=self.opr2.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += o_reg.get_register(self.opr1.value) + ' != ' + o_reg.get_register(self.opr2.value)
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr3.value + ';\n    ' + '}'

		return line, self.next_addr

	# branch less than zero instruction
	def do_bltz(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != bltz".format(hex(self.addr), self.ins), self.ins == 'bltz')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += o_reg.get_register(self.opr1.value) + ' < 0'
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr2.value + ';\n    ' + '}'

		return line, self.next_addr

	# branch on greater than zero instruction
	def do_bgtz(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != bgtz".format(hex(self.addr), self.ins), self.ins == 'bgtz')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += o_reg.get_register(self.opr1.value) + ' > 0'
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr2.value + ';\n    ' + '}'

		return line, self.next_addr

	# branch on greater than or equal to zero instruction
	def do_bgez(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != bgez".format(hex(self.addr), self.ins), self.ins == 'bgez')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += o_reg.get_register(self.opr1.value) + ' >= 0'
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr2.value + ';\n    ' + '}'

		return line, self.next_addr

	# branch on less than or equal to zero instruction
	def do_blez(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != blez".format(hex(self.addr), self.ins), self.ins == 'blez')

		line = o_func.get_comment(prefix='[branch]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		line += '\n    '
		line += 'if('
		line += o_reg.get_register(self.opr1.value) + ' <= 0'
		line += ') {'
		line += '\n        '
		if self.next_result is not None:
			line += self.next_result
			line += '\n        '
		line += 'goto ' + self.opr2.value + ';\n    ' + '}'

		return line, self.next_addr

	# branch address linked instruction
	def do_bal(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != bal".format(hex(self.addr), self.ins), self.ins == 'bal')

		line = ''
		if self.next_result is not None:
			line = self.next_result
			line += '\n    '
		line += o_func.get_comment(prefix='[branch]', opr1='$ra', opr2=self.opr1.value + '+ 4') + '\n    '
		line += o_func.get_comment(prefix='[branch]', opr1=self.opr1.value) + '\n    '
		line += 'goto ' + self.opr1.value + ';'

		return line, self.next_addr
