# mips_operand.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from base.operand import *

'''
	Object for Operand

	__init__ : Initialize operand information
	type : return operand type
	value : return operand value
'''
class MIPS_Operand(Operand):
	def __init__(self, optype, value):
		super(MIPS_Operand, self).__init__(optype, value)
		self._feature = self.query_feature()

	@property
	def feature(self):
		return self._feature
	
	def query_feature(self):
		if self.value == '':
			return OPND_FEATURE['None']

		# e.g) reg
		match = re.match(r"^(\$[0-9a-zA-Z]{2,4})$", self.value)
		if match:
			return OPND_FEATURE['Reg']

		# e.g) 0xC
		match = re.match(r"^(-?[0-9a-fA-Fx]+)$", self.value)
		if match:
			return OPND_FEATURE['Imm']

		# e.g) (aAddr - 0xC)($a0)
		match = re.match(r"^\(([0-9a-zA-Z_]+) ([-+] [0-9a-fA-Fx]+)\)\(([$0-9a-zA-Z]{3})\)$", self.value)
		if match:
			return OPND_FEATURE['Addr_Imm_Reg']

		# e.g) (aAddr+0xC - 0xC)($a0)
		match = re.match(r"^\(([0-9a-zA-Z_]+)([-+][0-9a-fA-Fx]+) ([-+] [0-9a-fA-Fx]+)\)\(([$0-9a-zA-Z]{3})\)$", self.value)
		if match:
			return OPND_FEATURE['Addr_Offset_Imm_Reg']

		# e.g) (aAddr - 0xC)
		match = re.match(r"^\(([0-9a-zA-Z_]+) ([-+] [0-9a-fA-Fx]+)\)$", self.value)
		if match:
			return OPND_FEATURE['Addr_Imm']

		# e.g) (aAddr+1 - 0xC)
		match = re.match(r"^\(([0-9a-zA-Z_]+)([+-][0-9a-fA-Fx]+) ([+-] [0-9a-fA-Fx]+)\)$", self.value)
		if match:
			return OPND_FEATURE['Addr_Imm']

		# e.g) 0xC($a0)
		match = re.match(r"^(-?[0-9a-fA-Fx]+)\(([$0-9a-zA-Z]{3})\)$", self.value)
		if match:
			return OPND_FEATURE['Reg_Imm']

		# e.g) 0x30+var_C($sp)
		match = re.match(r"^([0-9a-fA-Fx]+)\+[varg]{3}_([0-9a-fA-F]+)\(([$0-9a-zA-Z]{3})\)$", self.value)
		if match:
			return OPND_FEATURE['Imm_Imm_Reg']

		# e.g) 0x30+offset($sp)
		match = re.match(r"^([0-9a-fA-Fx]+)\+([0-9a-zA-Z]+)\(([$0-9a-zA-Z]{3})\)$", self.value)
		if match:
			return OPND_FEATURE['Imm_Imm_Reg']

		# e.g) 0x30+var_C
		match = re.match(r"^([0-9a-fA-Fx]+)\+[varg]{3}_([0-9a-fA-F]+)$", self.value)
		if match:
			return OPND_FEATURE['Imm_Imm']

		# e.g) addr
		match = re.match(r"^([0-9a-zA-Z_]+)$", self.value)
		if match:
			return OPND_FEATURE['Addr']

		print "[-] Not matched operand feature, operand : " + self.value
		return None

	def parse(self):
		check_assert("[-] Check operand feature, operand : {0}".format(self._value), self._feature)

		if self._feature == OPND_FEATURE['Reg']:
			# e.g) reg
			match = re.match(r"^(\$[0-9a-zA-Z]{2,4})$", self.value)
			if match:
				return (match.group(1))

		elif self._feature == OPND_FEATURE['Imm']:
			# e.g) 0xC
			match = re.match(r"^(0x[0-9a-fA-F]+)$", self.value)
			if match:
				return (match.group(1))

		elif self._feature == OPND_FEATURE['Addr_Imm_Reg']:
			# e.g) (aAddr - 0xC)($a0)
			match = re.match(r"^\(([0-9a-zA-Z_]+) ([-+] [0-9a-fA-Fx]+)\)\(([$0-9a-zA-Z]{3})\)$", self.value)
			if match:
				return (match.group(1), match.group(2), match.group(3))

		elif self._feature == OPND_FEATURE['Addr_Offset_Imm_Reg']:
			# e.g) (aAddr+0xC - 0xC)($a0)
			match = re.match(r"^\(([0-9a-zA-Z_]+)([-+][0-9a-fA-Fx]+) ([-+] [0-9a-fA-Fx]+)\)\(([$0-9a-zA-Z]{3})\)$", self.value)
			if match:
				return (match.group(1), match.group(2), match.group(3), match.group(4))

		elif self._feature == OPND_FEATURE['Addr_Imm']:
			# e.g) (aAddr - 0xC)
			match = re.match(r"^\(([0-9a-zA-Z_]+) ([-+] [0-9a-fA-Fx]+)\)$", self.value)
			if match:
				return (match.group(1), match.group(2))

			# e.g) (aAddr+1 - 0xC)
			match = re.match(r"^\(([0-9a-zA-Z_]+)([+-][0-9a-fA-Fx]+) ([+-] [0-9a-fA-Fx]+)\)$", self.value)
			if match:
				return (match.group(1), match.group(2), match.group(3))

		elif self._feature == OPND_FEATURE['Reg_Imm']:
			# e.g) 0xC($a0)
			match = re.match(r"^(-?[0-9a-fA-Fx]+)\(([$0-9a-zA-Z]{3})\)$", self.value)
			if match:
				return (match.group(1), match.group(2))

		elif self._feature == OPND_FEATURE['Imm_Imm_Reg']:
			# e.g) 0x30+var_C($sp)
			match = re.match(r"^([0-9a-fA-Fx]+)\+([varg]{3}_([0-9a-fA-F]+))\(([$0-9a-zA-Z]{3})\)$", self.value)
			if match:
				return (match.group(1), match.group(2), match.group(3), match.group(4))

			# e.g) 0x30+offset($sp)
			match = re.match(r"^([0-9a-fA-Fx]+)\+([0-9a-zA-Z]+)\(([$0-9a-zA-Z]{3})\)$", self.value)
			if match:
				return (match.group(1), match.group(2), match.group(2), match.group(3))
				
		elif self._feature == OPND_FEATURE['Imm_Imm']:
			# e.g) 0x30+var_C
			match = re.match(r"^([0-9a-fA-Fx]+)\+([varg]{3}_([0-9a-fA-F]+))$", self.value)
			if match:
				return (match.group(1), match.group(2), match.group(3))

		elif self._feature == OPND_FEATURE['Addr']:
			# e.g) aAddr
			match = re.match(r"^([0-9a-zA-Z_]+)$", self.value)
			if match:
				return OPND_FEATURE['Addr']

		elif self._feature == OPND_FEATURE['None']:
			return None

		else:
			print "[-] Unknown operand feature : {1}".format(self._feature)
			return None

	def is_expand_operand(self, reg, imm):
		# reg and imm type : string
		check_assert("[-] This function is provided for Addr_Imm_Reg or Addr_Offset_Imm_Reg operand features", 
			self._feature == OPND_FEATURE['Addr_Imm_Reg'] or self._feature == OPND_FEATURE['Addr_Offset_Imm_Reg'])
		check_assert("[-] Check reg value, {0} == o_reg.get_register({1})".format(reg, reg), idc.LocByName(reg) != 0xffffffff)

		try:
			if idc.LocByName(reg) + int(imm, 16) == 0:
				return True
			elif int(reg, 16) + int(imm, 16) == 0:
				return True
			else:
				return False
		except TypeError:
			print "[-] Unknown IDA error, Accept to omit a operand"
			return True

	def convert(self, o_reg=None):
		parsed = self.parse()
		if parsed is None:
			return self._value

		# e.g) reg
		if self._feature == OPND_FEATURE['Reg']:
			if o_reg:
				return o_reg.get_register(parsed[0])
			else:
				return parsed[0]

		# e.g) 0xC
		elif self._feature == OPND_FEATURE['Imm']:
			return parsed[0]

		# e.g) (aAddr - 0xC)($a0)
		elif self._feature == OPND_FEATURE['Addr_Imm_Reg']:
			reg = o_reg.get_register(parsed[2])
			try:
				if self.is_expand_operand(reg, parsed[1]):
					return parsed[0]
			except:
				# converting flow error, Temporarily allow this.
				if idc.LocByName(reg) == 0xffffffff:
					return parsed[0]

			imm = int(parsed[1], 16)
			addr = idc.LocByName(parsed[0])

			return hex(idc.LocByName(reg) + addr + imm).replace('L', '')

		# e.g) (aAddr+0xC - 0xC)($a0)
		elif self._feature == OPND_FEATURE['Addr_Offset_Imm_Reg']:
			reg = o_reg.get_register(parsed[3])
			if self.is_expand_operand(reg, parsed[2]):
				return parsed[0] + parsed[1]

			imm = int(parsed[2], 16)
			offset = int(parsed[1], 16)
			addr = idc.LocByName(parsed[0])

			return hex(idc.LocByName(reg) + addr + offset + imm).replace('L', '')

		# e.g) (aAddr - 0xC)
		elif self._feature == OPND_FEATURE['Addr_Imm']:
			if len(parsed) == 3:
				return hex(idc.LocByName(parsed[0]) + int(parsed[1], 16) + int(parsed[2], 16)).replace('L', '')
			else:
				return hex(idc.LocByName(parsed[0]) + int(parsed[1], 16)).replace('L', '')

		# e.g) 0xC($a0)
		elif self._feature == OPND_FEATURE['Reg_Imm']:
			if not o_reg.has_register(parsed[1]):
				return '*({0} + {1})'.format(parsed[1], parsed[0])
			else:
				try:
					reg = int(o_reg.get_register(parsed[1]), 16)
				except ValueError:
					return '*({0} + {1})'.format(o_reg.get_register(parsed[1]), parsed[0])

				imm = int(parsed[0], 16)

				return hex(reg + imm).replace('L', '')

		# e.g) 0x30+var_C($sp)
		elif self._feature == OPND_FEATURE['Imm_Imm_Reg']:
			return parsed[1]

		# e.g) 0x30+var_C
		elif self._feature == OPND_FEATURE['Imm_Imm']:
			return hex(int(parsed[1], 16) - int(parsed[3], 16))

		# e.g) aAddr
		elif self._feature == OPND_FEATURE['Addr']:
			return parsed[0]

		elif self._feature == OPND_FEATURE['None']:
			return None
			
		else:
			print "[-] check operand : " + self._value
			return self._value
