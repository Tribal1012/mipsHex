# asmutils.py

from define import *

import abc

'''
	assembly utils about operand
	__init__ : parsed operand information
	have_string : check variable which have string
	get_string : call have_string, then if valiable have string, return refered string by valiable
'''
class AsmUtils(object):
	__metaclass__ = abc.ABCMeta

	def __init__(self):
		pass

	@abc.abstractmethod
	def have_string(self, operand):
		pass

	@abc.abstractmethod
	def get_string(self, operand):
		pass
