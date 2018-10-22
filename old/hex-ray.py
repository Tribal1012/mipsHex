import mipsHex.mips_Iasm as mips_asm
import mipsHex.mips_function as mips_function
import mipsHex.mips_register as mips_register
from mipsHex.mips_asmutils import asmutils

from base.error import *
from base.define import ASM_TYPE, ARCHITECTURE

import idautils
import idc

VERSION = '0.12.1'

NEXTLINE = '\n'
TAB = '    '

class CustomHex:
	def __init__(self, arc):
		global NEXTLINE
		global TAB

		if arc == ARCHITECTURE['MIPS']:
			self.arc = ARCHITECTURE['MIPS']
			self.func = mips_function.MIPS_Function()
			self.reg = mips_register.MIPS_Register()
			self.asm = mips_asm.MIPS_IAsm()
		else:
			self.arc = None
			self.func = None
			self.reg = None
			self.asm = None

	def AppendRefAddr(self, addr, ref_list, to):
		if addr in ref_list:
			to += NEXTLINE
			to += NEXTLINE
			to += 'loc_' + hex(int(addr))[2:].upper() + ':'

		return to

	def AppendNewLine(self, line, to):
		if line:
			to += NEXTLINE + TAB + line

		return to
	
	def GetRefList(self, start=None, end=None):
		func_ref_list = list()
		if start != BADADDR:
			for item in FuncItems(start):
				# Check reference
				cross_refs = CodeRefsFrom(item, 1)
 		
 				temp_ref_list = list()
				# Convert from generator to list
				for ref in cross_refs:
					temp_ref_list.append(ref)
 		
 				# Collect ref_lists except temp_ref_list[0](next address)
				if len(temp_ref_list) >= 2:
					for i in range(1, len(temp_ref_list), 1):
						func_ref_list.append(temp_ref_list[i])
 		
 		# Deduplication
		temp_ref_list = list(set(func_ref_list))
		func_ref_list = list()
 		
 		for ref in temp_ref_list:
			if ref >= start and ref < end:
				func_ref_list.append(ref)
 		
 		func_ref_list.sort()
 		
 		return func_ref_list

	def GetFuncInfo(self):
		# Get current function's name and address using ida python
		func_name, func_addr = self.func.init_func()
		
		print "[+] Function name : " + func_name
		print "[+] Function address : " + hex(func_addr[0])

		self.func_ref_list = self.GetRefList(func_addr[0], func_addr[1])

		return func_name, func_addr

	def hex_ray(self, start, end):
		contents = ''

		current = start
		while current < end:
#			if current != start:
				# Write reference addresses
			contents = self.AppendRefAddr(current, self.func_ref_list, contents)

			# assmbly dispatch
			line, n_addr = self.asm.dispatch(current, self.reg, self.func)

			# apply dispatch result
			contents = self.AppendNewLine(line, contents)

			if n_addr:
				current = idc.NextHead(n_addr, end)
			else:
				current = idc.NextHead(current, end)

		return contents

	def mips(self, path=None):
		func_name, func_addr = self.GetFuncInfo()
		
		func_contents = self.hex_ray(func_addr[0], func_addr[1])

		if path:
			filename = path + '\\' + func_name + ".c"
		else:
			filename = func_name + ".c"

		with open(filename, "w") as fh:
			fh.write(self.func.function(func_contents))

if __name__ == '__main__':
	DEBUG = False

	o_hex = CustomHex(ARCHITECTURE['MIPS'])
	if DEBUG:
		func_name, func_addr = o_hex.GetFuncInfo()

		# print o_hex.asm.dispatch(here(), o_hex.reg, o_hex.func)
		# print o_hex.reg.mips_saved_register
	else:
		o_hex.mips()
