# asmutils.py

import abc

class AsmUtils(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self):
		self.info = {
			'sf':None,
			'var':None,
			'reg':None,
			'addr':None,
			'offset':None
		}

	@abc.abstractmethod
	def convert_to_var(self, operand):
		pass

	@abc.abstractmethod
	def parse_operand(self, operand, o_reg=None):
		pass
