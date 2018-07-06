# mips_asmutils.py

import re

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import base.asmutils as bau

import idc

'''
	mips assembly utils about operand
	__init__ : call super class's __init__
	have_string : check variable which have string
	get_string : call have_string, then if valiable have string, return refered string by valiable
	convert_var_naming : rename for general immediate values
	check_var_naming : It check the specific operand to have variable naming rule
	check_use_return : check a function's return value($v0)

	global MIPS_AsmUtils object : asmutils
'''
class MIPS_AsmUtils(bau.AsmUtils):
	def __init__(self):
		super(MIPS_AsmUtils, self).__init__()

	def have_string(self, operand):
		if operand[0] != 'a':
			return False

		loc_addr = idc.LocByName(operand)
		if idc.GetString(loc_addr) != '' and idc.isData(idc.GetFlags(loc_addr)):
			return True
		else:
			return False

	def get_string(self, operand):
		if self.have_string(operand):
			return '"' + idc.GetString(idc.LocByName(operand)) + '"'

		return None

	def convert_var_naming(self, val):
		match = re.match(r"^([0-9a-zA-Z_]+)$", val)
		if match:
			# variable naming rule
			if val[:2] == '0x':
				new_val = 'dword_' + val[2:]
			elif val[0] in '1234567890':
				new_val = 'ptr_' + val
			else:
				new_val = val
		else:
			new_val = ''
			for c in val:
				if c.isalnum() or c == '_':
					new_val += c

			new_val = self.check_var_naming(new_val)

		return new_val

	def check_var_naming(self, val):
		match = re.match(r"^([0-9a-zA-Z_]+)$", val)
		if match:
			return True
		else:
			return False

	def check_use_return(self, addr):
		next_addr = idc.NextHead(addr)

		ins = idc.GetMnem(next_addr)
		opr1 = idc.GetOpnd(next_addr, 0)

		if ins == 'lw' and opr1 == '$gp':
			return self.check_use_return(next_addr)
		
		opr2 = idc.GetOpnd(next_addr, 1)
		opr3 = idc.GetOpnd(next_addr, 2)
		if opr2 == '$v0' or opr3 == '$v0':
			return True
		
		ins_store = ('sb', 'sh', 'sw', 'swl', 'swr', 'ulw', 'usw')
		if ins not in ins_store and opr1 == '$v0':
			if opr3 is None or opr3 == '':
				return True
		
		return False

asmutils = MIPS_AsmUtils()