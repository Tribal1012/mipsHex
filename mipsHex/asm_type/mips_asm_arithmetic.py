# mips_asm_arithmetic.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from mips_asm import *

# instruction(arthmetic operation)
class MIPS_Asm_Arithmetic(MIPS_Asm):
	def __init__(self, addr):
		super(MIPS_Asm_Arithmetic, self).__init__(addr)

	# add instruction
	def do_add(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != add".format(hex(self.addr), self.ins), self.ins == 'add')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' + ' + o_reg.get_register(self.opr3.value) + ')')

			else:
				error("[-] address({0}), Not defined add opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='+')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' + ' + o_reg.get_register(self.opr2.value) + ')')

			else:
				error("[-] address({0}), Not defined add opr2 type({1})".format(hex(self.addr), self.opr2.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='+')

		else:
			error("[-] current({0}), Not defined add".format(hex(self.addr)))

		return comment, None

	# addi instruction
	def do_addi(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != addi".format(hex(self.addr), self.ins), self.ins == 'addi')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' + ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined addi opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='+')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' + ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined addi opr2 type({1})".format(hex(self.addr), self.opr2.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='+')

		else:
			error("[-] current({0}), Not defined addi".format(hex(self.addr)))

		return comment, None

	# addu instruction
	def do_addu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != addu".format(hex(self.addr), self.ins), self.ins == 'addu')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' + ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' + ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined addu opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='+')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' + ' + o_reg.get_register(self.opr2.value) + ')')

			elif self.opr2.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' + ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined addu opr2 type({1})".format(hex(self.addr), self.opr2.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='+')

		else:
			error("[-] current({0}), Not defined addu".format(hex(self.addr)))

		return comment, None

	# addiu instruction
	def do_addiu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != addiu".format(hex(self.addr), self.ins), self.ins == 'addiu')

		if self.get_operand_count() == 3:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				if o_reg.get_register(self.opr2.value) == '$sp' and self.opr3.feature == OPND_FEATURE['Imm_Imm']:
					# addiu opr1, sp, 0x50_var
					new_opr = MIPS_Operand(ASM_TYPE['Base_Idx_Disp'], self.opr3.value + '(' + o_reg.get_register(self.opr2.value) + ')')
					o_reg.set_register(self.opr1.value, new_opr.convert(o_reg))
				else:
					# addiu opr1, v0, opr3
					reg_val = o_reg.get_register(self.opr2.value)
					cvt_opr3 = self.opr3.convert(o_reg)
					if idc.LocByName(reg_val) != 0xffffffff:
						o_reg.set_register(self.opr1.value, hex(idc.LocByName(reg_val) + int(cvt_opr3, 16)))
					elif asmutils.isImmediate(reg_val, cvt_opr3):
						o_reg.set_register(self.opr1.value, '"' + idc.GetString(int(reg_val, 16) + int(cvt_opr3, 16)) + '"')
					else:
						o_reg.set_register(self.opr1.value, '(' + reg_val + ' + ' + cvt_opr3 + ')')

				comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='+')
			else:
				error("[-] current({0}), Not defined addiu operand2 type".format(hex(self.addr)))

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				# addiu opr1, v0
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' + ' + o_reg.get_register(self.opr2.value) + ')')

			elif self.opr2.type == ASM_TYPE['Imm']:
				if self.opr2.feature == OPND_FEATURE['Addr_Imm']:
					new_opr = MIPS_Operand(ASM_TYPE['Base_Idx_Disp'], self.opr2.value + '(' + self.opr1.value + ')')
					cvt_opr = new_opr.convert(o_reg)
					if asmutils.have_string(cvt_opr):
						c_string = asmutils.get_string(cvt_opr)
						o_reg.set_register(self.opr1.value, c_string)
					else:
						o_reg.set_register(self.opr1.value, cvt_opr)
				elif o_reg.get_register(self.opr1.value) == '$sp':
					# for skip prologue
					# need to parse a opnd_feature's reg for line 20
					pass
				else:
					# addiu v0, 1
					o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' + ' + self.opr2.value + ')')

			else:
				error("[-] current({0}), Not defined addiu operand type".format(hex(self.addr)))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='+')
		else:
			error("[-] current({0}), Not defined addiu".format(hex(self.addr)))			

		return comment, None

	# sub instruction
	def do_sub(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != sub".format(hex(self.addr), self.ins), self.ins == 'sub')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' - ' + o_reg.get_register(self.opr3.value) + ')')

			else:
				error("[-] address({0}), Not defined sub opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='-')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' - ' + o_reg.get_register(self.opr2.value) + ')')

			else:
				error("[-] address({0}), Not defined sub opr2 type({1})".format(hex(self.addr), self.opr2.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='-')

		else:
			error("[-] current({0}), Not defined sub".format(hex(self.addr)))

		return comment, None

	# subu instruction
	def do_subu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != subu".format(hex(self.addr), self.ins), self.ins == 'subu')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' - ' + o_reg.get_register(self.opr3.value) + ')')

			elif self.opr3.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' - ' + self.opr3.value + ')')

			else:
				error("[-] address({0}), Not defined subu opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='-')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' - ' + o_reg.get_register(self.opr2.value) + ')')

			elif self.opr2.type == ASM_TYPE['Imm']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' - ' + self.opr2.value + ')')

			else:
				error("[-] address({0}), Not defined subu opr2 type({1})".format(hex(self.addr), self.opr2.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='-')

		else:
			error("[-] current({0}), Not defined subu".format(hex(self.addr)))

		return comment, None

	# mul instruction
	def do_mul(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != mul".format(hex(self.addr), self.ins), self.ins == 'mul')

		if self.get_operand_count() == 3:
			if self.opr3.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr2.value) + ' * ' + o_reg.get_register(self.opr3.value) + ')')

			else:
				error("[-] address({0}), Not defined mul opr3 type({1})".format(hex(self.addr), self.opr3.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr2.value, opr3=self.opr3.value, operation='-')

		elif self.get_operand_count() == 2:
			if self.opr2.type == ASM_TYPE['Gen_Reg']:
				o_reg.set_register(self.opr1.value, '(' + o_reg.get_register(self.opr1.value) + ' * ' + o_reg.get_register(self.opr2.value) + ')')

			else:
				error("[-] address({0}), Not defined mul opr2 type({1})".format(hex(self.addr), self.opr2.type))

			comment = o_func.get_comment(opr1=self.opr1.value, opr2=self.opr1.value, opr3=self.opr2.value, operation='-')

		else:
			error("[-] current({0}), Not defined mul".format(hex(self.addr)))

		return comment, None

	# mult instruction
	def do_mult(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != mult".format(hex(self.addr), self.ins), self.ins == 'mult')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', '(' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' %% 0xFFFFFFFF')
		o_reg.set_register('$lo', '(' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' / 0xFFFFFFFF')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# multu instruction
	def do_multu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != multu".format(hex(self.addr), self.ins), self.ins == 'multu')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', '(' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' %% 0xFFFFFFFF')
		o_reg.set_register('$lo', '(' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' / 0xFFFFFFFF')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# div instruction
	def do_div(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != div".format(hex(self.addr), self.ins), self.ins == 'div')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', '(' + o_reg.get_register(self.opr1.value) + ' %% ' + opr2 + ')')
		o_reg.set_register('$lo', '(' + o_reg.get_register(self.opr1.value) + ' / ' + opr2 + ')')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# divu instruction
	def do_divu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != divu".format(hex(self.addr), self.ins), self.ins == 'divu')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', '(' + o_reg.get_register(self.opr1.value) + ' %% ' + opr2 + ')')
		o_reg.set_register('$lo', '(' + o_reg.get_register(self.opr1.value) + ' / ' + opr2 + ')')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# mul and add instruction
	def do_madd(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != madd".format(hex(self.addr), self.ins), self.ins == 'madd')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', o_reg.get_register('$hi') + '+ (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' %% 0xFFFFFFFF')
		o_reg.set_register('$lo', o_reg.get_register('$lo') + '+ (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' / 0xFFFFFFFF')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# mul and addu instruction
	def do_maddu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != maddu".format(hex(self.addr), self.ins), self.ins == 'maddu')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', o_reg.get_register('$hi') + '+ (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' %% 0xFFFFFFFF')
		o_reg.set_register('$lo', o_reg.get_register('$lo') + '+ (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' / 0xFFFFFFFF')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# mul and sub instruction
	def do_msub(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != msub".format(hex(self.addr), self.ins), self.ins == 'msub')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', o_reg.get_register('$hi') + '- (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' %% 0xFFFFFFFF')
		o_reg.set_register('$lo', o_reg.get_register('$lo') + '- (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' / 0xFFFFFFFF')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# mul and subu instruction
	def do_msubu(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != msubu".format(hex(self.addr), self.ins), self.ins == 'msubu')
		check_assert("[-] Check operand count, current({0}) : {1}".format(hex(self.addr), self.get_operand_count()), self.get_operand_count() == 2)

		opr2 = o_reg.get_register(self.opr2.value) if self.opr2.type == ASM_TYPE['Gen_Reg'] else self.opr2.value

		o_reg.set_register('$hi', o_reg.get_register('$hi') + '- (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' %% 0xFFFFFFFF')
		o_reg.set_register('$lo', o_reg.get_register('$lo') + '- (' + o_reg.get_register(self.opr1.value) + ' * ' + opr2 + ')' + ' / 0xFFFFFFFF')

		comment = o_func.get_comment(opr1='$hi, $lo', opr2=o_reg.get_register(self.opr1.value), opr3=opr2, operation='*')

		return comment, None

	# sign extend byte
	def do_seb(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != seb".format(hex(self.addr), self.ins), self.ins == 'seb')

		if self.get_operand_count() == 2:
			check_assert("[-] Check opr2, current({0})".format(hex(self.addr)), self.opr2.type == ASM_TYPE['Gen_Reg'])
			check_assert("[-] Check opr1, current({0})".format(hex(self.addr)), self.opr1.type == ASM_TYPE['Gen_Reg'])
			
			o_reg.set_register(self.opr1.value, '(int8_t)(' + o_reg.get_register(self.opr2.value) + ')')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2='(int8_t)(' + o_reg.get_register(self.opr2.value) + ')')

		elif self.get_operand_count() == 1:
			check_assert("[-] Check opr1, current({0})".format(hex(self.addr)), self.opr1.type == ASM_TYPE['Gen_Reg'])
			
			o_reg.set_register(self.opr1.value, '(int8_t)(' + o_reg.get_register(self.opr1.value) + ')')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2='(int8_t)(' + o_reg.get_register(self.opr1.value) + ')')

		else:
			error("[-] current({0}), Not defined seb".format(hex(self.addr)))

		return comment, None

	# sign extend half word
	def do_seh(self, o_reg, o_func):
		check_assert("[-] Check ins, current({0}) : {1} != seh".format(hex(self.addr), self.ins), self.ins == 'seh')

		if self.get_operand_count() == 2:
			check_assert("[-] Check opr2, current({0})".format(hex(self.addr)), self.opr2.type == ASM_TYPE['Gen_Reg'])
			check_assert("[-] Check opr1, current({0})".format(hex(self.addr)), self.opr1.type == ASM_TYPE['Gen_Reg'])
			
			o_reg.set_register(self.opr1.value, '(int16_t)(' + o_reg.get_register(self.opr2.value) + ')')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2='(int16_t)(' + o_reg.get_register(self.opr2.value) + ')')

		elif self.get_operand_count() == 1:
			check_assert("[-] Check opr1, current({0})".format(hex(self.addr)), self.opr1.type == ASM_TYPE['Gen_Reg'])
			
			o_reg.set_register(self.opr1.value, '(int16_t)(' + o_reg.get_register(self.opr1.value) + ')')

			comment = o_func.get_comment(opr1=self.opr1.value, opr2='(int16_t)(' + o_reg.get_register(self.opr1.value) + ')')

		else:
			error("[-] current({0}), Not defined seh".format(hex(self.addr)))

		return comment, None
