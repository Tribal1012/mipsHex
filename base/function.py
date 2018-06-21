# functopm.py

import idautils
import idc

'''
	helper for make a function
	set_local_var : set a local variable in the local_var list
	get_local_var : get a local variable using key
	set_argument : set a argument in the arguments list
	init_func_from_ida : get current function's address and name from IDA
	make : return function which is string type using member
'''
class Function(object):
	def __init__(self):
		self.func_name = ''
		self.ret_type = 'void'
		self.arguments = list()
		self.local_var = dict()
		self.func_contents = ''
		self.func_addr = tuple()

	def set_local_var(self, key, value):
		doset = True
		for arg in self.arguments:
			if key.find(arg) != -1:
				doset = False

		if doset:
			self.local_var[key] = value

	def get_local_var(self, key):
		if key in self.local_var.keys():
			return self.local_var[key]

		return None

	def set_argument(self, value):
		if value not in self.arguments:
			self.arguments.append(value)

	def init_func_from_ida(self):
		# get current address
		# and get the function address from current address
		current_addr = idc.here()
		self.func_name = idc.GetFunctionName(current_addr)
		for chunk in idautils.Chunks(idc.LocByName(self.func_name)):
			self.func_addr = chunk

			return self.func_name, self.func_addr

	def make(self, contents=None):
		TAB = '    ' # 4 space
		NEXTLINE = '\n'

		function = 'return_type {0} (arguments_info)'.format(self.func_name)
		function += NEXTLINE + '{'
		function += 'function_contents'
		function += NEXTLINE + '}'

		if len(self.arguments) != 0:
			arguments = 'uint32_t ' + ', uint32_t '.join(self.arguments)
		else:
			arguments = ''

		local_var = ''
		if len(self.local_var) != 0:
			for item in self.local_var:
				local_var += NEXTLINE + TAB
				local_var += 'uint32_t '	# variable type
				local_var += item			# variable name
				local_var += ';'

		# replace information
		function = function.replace('return_type', self.ret_type)
		function = function.replace('arguments_info', arguments)

		if contents is None:
			try:
				function = function.replace('function_contents', local_var + NEXTLINE*2 + TAB + self.func_contents)
			except:
				pass
		else:
			function = function.replace('function_contents', local_var + NEXTLINE*2 + TAB + contents)
			self.func_contents = contents

		return function
