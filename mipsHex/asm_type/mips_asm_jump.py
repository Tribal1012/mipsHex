# mips_asm_jump.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

import idc

# instruction(must branch, jump)
class MIPS_Asm_Jump(MIPS_Asm):
	def __init__(self, addr, dispatch, o_reg, o_func):
		super(MIPS_Asm_Jump, self).__init__(addr)

		self.next_addr = idc.NextHead(addr)
		self.next_result, n_addr = dispatch(self.next_addr, o_reg, o_func)
		check_assert("[-] address({0}), dispatch error in jump".format(hex(self.next_addr)), n_addr is None or n_addr == self.next_addr)

	# jump instruction
	def do_j(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != j".format(hex(self.addr), self.ins), self.ins == 'j')

		comment = ''
		if self.next_result is not None:
			comment = self.next_result
			comment += '\n    '
		comment += o_func.get_comment(prefix='[jump]', opr1=self.opr1.value) + '\n    '
		line = 'goto ' + self.opr1.value + ';'

		return comment + line, self.next_addr# idc.PrevHead(idc.LocByName(self.opr1.value))

	# jump + address + linked instruction
	def do_jal(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != jal".format(hex(self.addr), self.ins), self.ins == 'jal')

		comment =  o_func.get_comment(prefix='[call]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		comment += '\n    '

		arg_count = o_reg.get_func_arg_count(self.addr)
		line = self.opr1.value
		line += '('
		line += o_reg.get_func_arg()#arg_count)
		line += ')' + ';'

		if asmutils.check_use_return(self.next_addr):
			o_reg.set_register('$v0', 'v0_' + self.opr1.value)
			if self.next_result is not None:
				comment = self.next_result + '\n    ' + comment
			comment += '$v0 = '
			comment += line
			comment += '\n    '
			comment += o_func.get_comment(prefix='[return value]', opr1='$v0', opr2=line)

			return comment, self.next_addr

		if self.next_result is not None:
			comment = self.next_result + '\n    ' + comment

		return comment + line, self.next_addr

	# jump register instruction
	def do_jr(self, o_reg, o_func):
		# equal ret
		if self.opr1.value == '$ra':
			return None, None

		comment = ''
		if self.next_result is not None:
			comment = self.next_result
			comment += '\n    '
		comment += o_func.get_comment(prefix='[jump]', opr1=self.opr1.value) + '\n    '
		line = 'goto ' + o_reg.get_register(self.opr1.value) + ';'

		return comment + line, self.next_addr

	# jump register + address + linked instruction
	def do_jalr(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != jalr".format(hex(self.addr), self.ins), self.ins == 'jalr')

		comment =  o_func.get_comment(prefix='[call]', opr2=o_reg.get_register(self.opr1.value), opr3=self.opr1.value, operation='<--') 
		comment += '\n    '

		arg_count = o_reg.get_func_arg_count(self.addr)
		line = o_reg.get_register(self.opr1.value)
		line += '('
		line += o_reg.get_func_arg()#arg_count)
		line += ')' + ';'

		if asmutils.check_use_return(self.next_addr):
			o_reg.set_register('$v0', 'v0_' + o_reg.get_register(self.opr1.value))
			if self.next_result is not None:
				comment = self.next_result + '\n    ' + comment
			comment += '$v0 = '
			comment += line
			comment += '\n    '
			comment += o_func.get_comment(prefix='[return value]', opr1='$v0', opr2=line)

			return comment, self.next_addr

		if self.next_result is not None:
			comment = self.next_result + '\n    ' + comment

		return comment + line, self.next_addr
