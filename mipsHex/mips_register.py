# mips_register.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import base.register as br

'''
	Store mips register information
	And provide interfaces about register

	__init__ : define mips register
	get_register : search a mips register, and return mips register value
	has_register : check to exist the mips register
	set_register : search a mips register, and set mips register value
	get_func_arg : get function arguments list from mips argument registers
	isargument : Is this register argument register?
	issaved : Is this register saved register?
'''
class MIPS_Register(br.Register):
	def __init__(self):
		super(MIPS_Register, self).__init__()
		self.mips_value_register = {'$v0':None, '$v1':None, '$zero':'0'}
		self.mips_argument_register = {'$a0':None, '$a1':None, '$a2':None, '$a3':None}
		self.mips_temp_register = {'$t0':None, '$t1':None, '$t2':None, '$t3':None, '$t4':None, '$t5':None, '$t6':None, '$t7':None, '$t8':None, '$t9':None}
		self.mips_saved_register = {'$s0':None, '$s1':None, '$s2':None, '$s3':None, '$s4':None, '$s5':None, '$s6':None, '$s7':None}
		self.mips_stack_register = {'$sp':'$sp', '$fp':'$fp', '$ra':'$ra', '$gp':'$gp'}
		self.register_list = (self.mips_value_register, self.mips_argument_register, self.mips_temp_register, self.mips_saved_register, self.mips_stack_register)

	def get_register(self, register):
		for line in self.register_list:
			for key, valie in line.items():
				if key == register:
					return line[key]
		return None

	def has_register(self, register):
		for line in self.register_list:
			for key, value in line.items():
				if key == register:
					return True
		return False

	def set_register(self, register, value):
		for line in self.register_list:
			for key,_d in line.items():
				if key == register:
					line[key] = value

	def get_func_arg(self):
		arguments = list()
		for value in self.mips_argument_register.values():
			if value is None:
				break
			else:
				arguments.append(value)

		return str(arguments).replace('\'', '')[1:-1]

	def isargument(self, register):
		return True if register in self.mips_argument_register.keys() else False
		
	def issaved(self, register):
		return True if register in self.mips_saved_register.keys() else False
