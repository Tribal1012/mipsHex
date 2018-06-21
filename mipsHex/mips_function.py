# mips_function.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import base.function as bf
'''
	helper for make a function
	set_local_var : set a local variable in the local_var list
	get_local_var : get a local varibale using key
	set_argument : set a argument in the arguments
	init_func : get current function's address and name from IDA
	function : return function which is string type using member
'''
class MIPS_Function(bf.Function):
	def __init__(self):
		super(MIPS_Function, self).__init__()

	def set_local_var(self, key, value):
		super(MIPS_Function, self).set_local_var(key, value)

	def get_local_var(self, key):
		return super(MIPS_Function, self).get_local_var(key)

	def set_argument(self, value):
		super(MIPS_Function, self).set_argument(value)

	def init_func(self):
		super(MIPS_Function, self).init_func_from_ida()

		return self.func_name, self.func_addr

	def function(self, contents=None):
		return super(MIPS_Function, self).make(contents)
		