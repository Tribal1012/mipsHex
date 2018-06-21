# mips_asmutils.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import base.asmutils as bau
import re

class MIPS_AsmUtils(bau.AsmUtils):
	def __init__(self):
		super(MIPS_AsmUtils, self).__init__()
		pass

	def convert_to_var(self, operand, o_reg=None):
		parsed = self.parse_operand(operand)

		if parsed is None:
			return operand

		if o_reg and parsed['reg']:
			reg = o_reg.get_register(parsed['reg'])
			if reg is None:
				reg = parsed['reg']
		else:
			reg = parsed['reg']

		if parsed['sf'] is None:
			if parsed['addr'] is None:
				if parsed['offset'] and parsed['reg']:
					# syntax e.g) 0x3C($a0)
					return '*({0}+{1})'.format(reg, parsed['offset'])
				else:
					print "[-] check operand : " + operand
					return operand
			elif parsed['reg']:
				if parsed['offset']:
					# syntax e.g) (gidpd_tracefp - 0x7032AC)($s3)
					return '*({0}+({1} + {2}))'.format(parsed['reg'], parsed['addr'], parsed['offset'])
			else:
				if parsed['offset']:
					# syntax e.g) (aSSetToSoftlimi - 0x590000)
					return operand
		else:
			if parsed['var']:
				if parsed['reg']:
					# syntax e.g) 0x30+var_8($sp)
					return 'v{0}'.format((int(parsed['var'], 16) - 8) / 4)
				else:
					# syntax e.g) 0x30+var_8
					return hex(int(parsed['sf'], 16) - int(parsed['var'], 16))
			else:
				print "[-] check operand : " + operand
				return operand

	def parse_operand(self, operand):
		# syntax e.g) (gidpd_tracefp - 0x7032AC)($s3)
		match = re.match(r"^\(([0-9a-zA-Z_]+) ([-+]) ([0-9a-fA-Fx]+)\)\(([$0-9a-zA-Z]{3})\)$", operand)
		if match:
			self.info['sf'] = None
			self.info['var'] = None
			self.info['addr'] = match.group(1)
			self.info['offset'] = match.group(3)
			self.info['reg'] = match.group(4)

			if match.group(2) == '-':
				self.info['offset'] = match.group(2) + self.info['offset']

			return self.info

		# syntax e.g) (aSSetToSoftlimi - 0x590000)
		match = re.match(r"^\(a([0-9a-zA-Z_]+) ([-+]) ([0-9a-fA-Fx]+)\)$", operand)
		if match:
			self.info['sf'] = None
			self.info['var'] = None
			self.info['reg'] = None
			self.info['addr'] = match.group(1)
			self.info['offset'] = match.group(3)

			if match.group(2) == '-':
				self.info['offset'] = match.group(2) + self.info['offset']

			return self.info

		# syntax e.g) 0x30+var_8($sp)
		match = re.match(r"^([0-9a-fA-Fx]+)\+var_([0-9a-fA-F]+)\(([$0-9a-zA-Z]{3})\)$", operand)
		if match:
			self.info['sf'] = match.group(1)
			self.info['var'] = match.group(2)
			self.info['reg'] = match.group(3)
			self.info['addr'] = None
			self.info['offset'] = None

			return self.info
		
		match = re.match(r"^([0-9a-fA-Fx]+)\+var_([0-9a-fA-F]+)$", operand)
		# syntax e.g) 0x30+var_8
		if match:
			self.info['sf'] = match.group(1)
			self.info['var'] = match.group(2)
			self.info['reg'] = None
			self.info['addr'] = None
			self.info['offset'] = None

			return self.info
		
		# syntax e.g) 0x3C($a0)
		match = re.match(r"^([0-9a-fA-Fx]+)\(([$0-9a-zA-Z]{3})\)$", operand)
		if match:
			self.info['offset'] = match.group(1)
			self.info['reg'] = match.group(2)
			self.info['sf'] = None
			self.info['var'] = None
			self.info['addr'] = None

			return self.info

		print "[-] it's regular expression error in parse_operand"
		print "    operand : " + operand

		self.info['sf'] = None
		self.info['var'] = None
		self.info['reg'] = None
		self.info['addr'] = None
		self.info['offset'] = None

		return None

asmutils = MIPS_AsmUtils()