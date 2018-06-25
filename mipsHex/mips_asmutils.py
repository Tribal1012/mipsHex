# mips_asmutils.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

import base.asmutils as bau
import re

import idc

'''
	mips assembly utils about operand
	__init__ : call super class's __init__
	convert_operand : convert from operand to the local variable feature
	parse_operand : parse operand datas
	have_string : check variable which have string
	get_string : call have_string, then if valiable have string, return refered string by valiable

	global MIPS_AsmUtils object : asmutils
'''
class MIPS_AsmUtils(bau.AsmUtils):
	def __init__(self):
		super(MIPS_AsmUtils, self).__init__()
		pass

	def convert_operand(self, operand, o_reg=None):
		parsed = self.parse_operand(operand)

		if parsed is None:
			return operand

		if o_reg and parsed['reg']:
			reg = o_reg.get_register(parsed['reg'])

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
				if o_reg and parsed['offset']:
					# syntax e.g) (gidpd_tracefp - 0x7032AC)($s3)
					reg_val = idc.LocByName(o_reg.get_register(parsed['reg']))
					addr_val = idc.LocByName(parsed['addr'])

					return hex(reg_val + addr_val + int(parsed['offset'], 16))[:-1]	# L
				else:
					print "[-] please o_reg argument, " + operand
					return operand
			else:
				if parsed['offset']:
					# syntax e.g) (aSSetToSoftlimi - 0x590000)
					return hex(idc.LocByName(parsed['addr']) + int(parsed['offset'], 16))[:-1] # L
				else:
					print "[-] don't have offset..." + operand
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
		match = re.match(r"^\(([0-9a-zA-Z_]+) ([-+]) ([0-9a-fA-Fx]+)\)$", operand)
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

	def have_string(self, operand):
		if operand[0] != 'a':
			return False

		loc_addr = idc.LocByName(operand)
		if idc.GetString(loc_addr) != '':
			return True
		else:
			return False

	def get_string(self, operand):
		if have_string(operand):
			return idc.GetString(idc.LocByName(operand))

		return None

	def check_var_naming(self, val):
		match = re.match(r"^([0-9a-zA-Z]+)$", val)
		if match:
			# variable naming rule
			if val[:2] == '0x':
				new_val = 'dword_' + val[2:]
			elif val[0] in '1234567890':
				new_val = 'ptr_' + val
			else:
				new_val = val
		else:
			new_val = ''
			for c in val:
				if c.isalnum() or c == '_':
					new_val += c

			new_val = self.check_var_naming(new_val)

		return new_val

asmutils = MIPS_AsmUtils()