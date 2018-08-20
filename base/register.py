# register.py

from abc import *

'''
	Store register information
	And provide interfaces about register
'''
class Register(object):
	__metaclass__ = ABCMeta

	def __init__(self):
		self.register_list = []

	@abstractmethod
	def get_register(self, register):
		pass

	@abstractmethod
	def set_register(self, register, value):
		pass

	@abstractmethod
	def get_func_arg(self, count=None):
		pass
		