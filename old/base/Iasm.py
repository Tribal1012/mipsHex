# Iasm.py

from error import error, check_assert

import abc

'''
	Assembly interface
	__init__ : nothing
	dispatch : support call specific assembly
'''
class IAsm(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self):
		pass

	# Find instruction type and call 'do_(instruction)' method
	@abc.abstractmethod
	def dispatch(self, addr, o_reg, o_func):
		pass