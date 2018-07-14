# operand.py

import idc

from error import error, check_assert
from define import OPND_FEATURE

from abc import *
import re

'''
	Object for Operand

	__init__ : Initialize operand information
	type : return operand type
	value : return operand value
'''
class Operand(object):
	__metaclass__ = ABCMeta

	def __init__(self, type, value):
		self._type = type
		self._value = value

	@property
	def type(self):
		return self._type

	@property
	def value(self):
		return self._value

	@abstractmethod
	def query_feature(self):
		pass

	@abstractmethod
	def parse(self):
		pass

	@abstractmethod
	def convert(self, o_reg):
		pass
