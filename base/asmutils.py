# asmutils.py

import abc

'''
	assembly utils about operand
	__init__ : parsed operand information
	convert_operand : convert from operand to the local variable feature
	parse_operand : parse operand datas
'''
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
	def convert_operand(self, operand):
		pass

	@abc.abstractmethod
	def parse_operand(self, operand, o_reg=None):
		pass
