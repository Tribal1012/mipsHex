# mips_asm_arithmetic.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(arthmetic operation)
class MIPS_Asm_Arithmetic(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Arithmetic, self).__init__(addr)

	# addiu instruction
	def do_addiu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != addiu".format(hex(self.addr), self.ins), self.ins == 'addiu')

		if self.opr2.type == asm_type['Gen_Reg']:
			if self.opr3:
				if self.opr3.value[1:].find('+') != -1 or self.opr3.value[1:].find('-') != -1: 
					if self.opr2.value == '$sp':
						new_opr = asmutils.convert_operand(self.opr3.value + '(' + self.opr2.value + ')', o_reg)
						o_reg.set_register(self.opr1.value, new_opr)
					else:
						reg_val = o_reg.get_register(self.opr2.value)
						new_opr = asmutils.convert_operand(self.opr3.value)
						o_reg.set_register(self.opr1.value, hex(idc.LocByName(reg_val) + int(new_opr, 16)))
				else:
					error("[-] current({0}), Not defined addiu operand3 type".format(hex(self.addr)))
			else:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '+' + o_reg.get_register(self.opr2.value) + ')')
		elif self.opr2.type == asm_type['Imm']:
			if self.opr2.value[1:].find('+') != -1 or self.opr2.value[1:].find('-') != -1:
				parsed = asmutils.parse_operand(self.opr2.value + '(' + self.opr1.value + ')')
				if int(parsed['offset'], 16) == idc.LocByName(o_reg.get_register(parsed['reg'])) * -1:
					c_string = asmutils.get_string(parsed['addr'])
					if c_string:
						o_reg.set_register(self.opr1.value, c_string)
					else:
						o_reg.set_register(self.opr1.value, parsed['addr'])
				else:
					print "[-] cause : " + parsed['offset'] + ", " + parsed['reg']
					error("[-] current({0}), operand2 parse error".format(hex(self.addr)))
			else:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '+' + self.opr2.value + ')')
		else:
			error("[-] current({0}), Not defined addiu operand type".format(hex(self.addr)))

		return None, None

	# addu instruction
	def do_addu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != addu".format(hex(self.addr), self.ins), self.ins == 'addu')

		if self.opr2.type == asm_type['Gen_Reg']:
			if self.opr3:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '+' + self.opr3.value + ')')
			else:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '+' + self.opr2.value + ')')
		else:
			error("[-] current({0}), Not defined addu operand type".format(hex(self.addr)))

		return None, None

	# subu instruction
	def do_subu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != subu".format(hex(self.addr), self.ins), self.ins == 'subu')

		if self.opr2.type == asm_type['Gen_Reg']:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + '-' + self.opr3.value + ')')
		elif self.opr2.type == asm_type['Imm']:
			o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + '-' + self.opr2.value + ')')
		else:
			error("[-] current({0}), Not defined subu operand type".format(hex(self.addr)))

		return None, None
