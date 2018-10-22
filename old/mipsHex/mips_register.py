# mips_register.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from base.error import error, check_assert
import base.register as br

import idc

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
	get_func_arg_count : util for get_func_arg method
'''
class MIPS_Register(br.Register):
	def __init__(self):
		super(MIPS_Register, self).__init__()
		self.mips_value_register = {'$v0':None, '$v1':None, '$zero':'0'}
		self.mips_argument_register = {'$a0':None, '$a1':None, '$a2':None, '$a3':None}
		self.mips_temp_register = {'$t0':None, '$t1':None, '$t2':None, '$t3':None, '$t4':None, '$t5':None, '$t6':None, '$t7':None, '$t8':None, '$t9':None}
		self.mips_saved_register = {'$s0':None, '$s1':None, '$s2':None, '$s3':None, '$s4':None, '$s5':None, '$s6':None, '$s7':None}
		self.mips_stack_register = {'$sp':'$sp', '$fp':'$fp', '$ra':'$ra', '$gp':'$gp'}
		self.mips_special_register = {'$pc':'$pc'}
		self.mips_accumulator = {'$lo':None, '$hi':None}
		self.register_list = (self.mips_value_register, self.mips_argument_register, self.mips_temp_register, self.mips_saved_register, self.mips_stack_register, self.mips_special_register, self.mips_accumulator)

	def get_register(self, register):
		for line in self.register_list:
			for key, valie in line.items():
				if key == register:
					if line[key]:
						return line[key]
					else:
						return register
						
		return register

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

	def copy(self, o_reg=None):
		if o_reg:
			if not hasattr(o_reg, 'register_list'):
				return None

			for key in self.mips_value_register.keys():
				self.mips_value_register[key] = o_reg.mips_value_register[key]

			for key in self.mips_argument_register.keys():
				self.mips_argument_register[key] = o_reg.mips_argument_register[key]

			for key in self.mips_temp_register.keys():
				self.mips_temp_register[key] = o_reg.mips_temp_register[key]

			for key in self.mips_saved_register.keys():
				self.mips_saved_register[key] = o_reg.mips_saved_register[key]

			for key in self.mips_stack_register.keys():
				self.mips_stack_register[key] = o_reg.mips_stack_register[key]

			for key in self.mips_special_register.keys():
				self.mips_special_register[key] = o_reg.mips_special_register[key]

			for key in self.mips_accumulator.keys():
				self.mips_accumulator[key] = o_reg.mips_accumulator[key]

			return self

		# Copy itself
		else:
			o_reg = MIPS_Register()
			o_reg.copy(self)

			return o_reg

	def get_func_arg(self, count=None):
		arguments = list()
		for value in self.mips_argument_register.values():
			if value is None:
				break
			else:
				arguments.append(value)

		if count is None or count > 4 :
			return str(arguments).replace('\'', '')[1:-1]
		else:
			arguments = arguments[:count]
			return str(arguments).replace('\'', '')[1:-1]

	def isargument(self, register):
		return True if register in self.mips_argument_register.keys() else False
		
	def issaved(self, register):
		return True if register in self.mips_saved_register.keys() else False

	def get_func_arg_count(self, addr):
		check_assert("[-] Invalid next_addr : {0}".format(hex(addr)), idc.GetMnem(addr) in ('jal', 'jalr'))

		next_addr = idc.NextHead(addr)
		
		ins = idc.GetMnem(next_addr)
		org1 = idc.GetOpnd(next_addr, 0)

		if ins == 'nop':
			return 0

		if self.isargument(org1):
			return int(org1[2])
		else:
			# unknown function arguments
			return 4