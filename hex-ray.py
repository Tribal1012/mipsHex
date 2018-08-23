import mipsHex.mips_Iasm as mips_asm
import mipsHex.mips_function as mips_function
import mipsHex.mips_register as mips_register
from mipsHex.mips_asmutils import asmutils

from base.error import *
from base.define import ASM_TYPE

import idautils
import idc

VERSION = 0.10

NEXTLINE = '\n'
TAB = '    '

ARCHITECTURE = {
	'MIPS':0x0
}
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
			to += 'loc_' + hex(addr)[2:-1].upper() + ':'

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

	def GetBranchList(self, start=None, end=None):
		branch_list = list()

		current = start
		if self.arc == ARCHITECTURE['MIPS']:
			branch_obj = self.asm.mips_asm_class['branch']
			jump_obj = self.asm.mips_asm_class['jump']

			while current <= end:
				method = 'do_' + idc.GetMnem(current)
				if hasattr(branch_obj, method) or hasattr(jump_obj, method):
					if idc.GetOpType(current, 0) == ASM_TYPE['Imm_Near_Addr']:
						opr = idc.LocByName(idc.GetOpnd(current, 0))
						if opr in self.func_ref_list:
							branch_list.append(hex(opr))
					elif idc.GetOpType(current, 1) == ASM_TYPE['Imm_Near_Addr']:
						opr = idc.LocByName(idc.GetOpnd(current, 1))
						if opr in self.func_ref_list:
							branch_list.append(hex(opr))
					elif idc.GetOpType(current, 2) == ASM_TYPE['Imm_Near_Addr']:
						opr = idc.LocByName(idc.GetOpnd(current, 2))
						if opr in self.func_ref_list:
							branch_list.append(hex(opr))

				current = idc.NextHead(current, end)

		branch_list = list(set(branch_list))
		branch_list.sort()

		return branch_list

	def ComputeBranchLink(self, start, end):
		branch_link = dict()
		if len(self.func_ref_list) != 0:
			branch_link[hex(start)] = self.GetBranchList(start, self.func_ref_list[0])
			for i in range(len(self.func_ref_list)):
				if i == len(self.func_ref_list)-1:
					branch_link[hex(self.func_ref_list[i])] = self.GetBranchList(self.func_ref_list[i], end)
				else:
					branch_link[hex(self.func_ref_list[i])] = self.GetBranchList(self.func_ref_list[i], self.func_ref_list[i+1])
		else:
			branch_link[hex(start)] = list()

		return branch_link

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
		while current <= end:
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

		branch_link =  self.ComputeBranchLink(func_addr[0], func_addr[1])
		# print branch_link

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
		o_hex.GetFuncInfo()

		print o_hex.asm.dispatch(here(), o_hex.reg, o_hex.func)
		print o_hex.reg.mips_saved_register
	else:
		o_hex.mips()
