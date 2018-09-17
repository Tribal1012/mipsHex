import mipsHex.mips_Iasm as mips_asm
import mipsHex.mips_function as mips_function
import mipsHex.mips_register as mips_register
from mipsHex.mips_asmutils import asmutils

from base.error import *
from base.define import ASM_TYPE, ARCHITECTURE

from branch import BranchManager

import idautils
import idc

import Queue

VERSION = 0.11

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
			self.bmgr = BranchManager(ARCHITECTURE['MIPS'])
		else:
			self.arc = None
			self.func = None
			self.reg = None
			self.asm = None
			self.bmgr = None

	def AppendRefAddr(self, addr, ref_list, to):
		if addr in ref_list:
			to += NEXTLINE
			to += NEXTLINE
			to += 'loc_' + hex(int(addr))[2:].upper() + ':'

			self.bmgr.InsertRegStatus(self.last_branch, self.reg)
#			try:
#				ref_list.remove(self.last_branch)
#			except:
#				print "[-] Addr : " + hex(self.last_branch)

			self.last_branch = addr

		return to

	def AppendNewLine(self, line, to):
		if line:
			to += NEXTLINE + TAB + line

		return to

	def GetFuncInfo(self):
		# Get current function's name and address using ida python
		func_name, func_addr = self.func.init_func()
		
		print "[+] Function name : " + func_name
		print "[+] Function address : " + hex(func_addr[0])

		self.bmgr.InitRefList(func_addr[0], func_addr[1])
		self.func_ref_list = self.bmgr.func_ref_list

		self.bmgr.InsertRegStatus(func_addr[0], self.reg)

		return func_name, func_addr

	def hex_ray(self, start, end):
		contents = ''

		current = start
		self.last_branch = start
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

		self.bmgr.InsertRegStatus(self.last_branch, self.reg)

		return contents

	def mips(self, path=None):
		func_name, func_addr = self.GetFuncInfo()
		branch_process = self.bmgr.ComputeBranchProcess(func_addr)
		
		func_contents = ''
		while branch_process.qsize():
			try:
				branch = branch_process.get_nowait()
			except Queue.Empty:
				continue

			self.reg = self.bmgr.GetRegStatus(branch['base'])
			if self.reg:
				func_contents += self.hex_ray(branch['start'], branch['end'])
			elif branch['start'] == branch['base']:
				self.reg = mips_register.MIPS_Register()
				func_contents += self.hex_ray(branch['start'], branch['end'])
			else:
				branch_process.put_nowait(branch)

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

		bmgr = BranchManager(ARCHITECTURE['MIPS'])
		bmgr.InitRefList(func_addr[0], func_addr[1])
		link = bmgr.ComputeBranchLinkEx(func_addr[0], func_addr[1])
		key_list = link.keys()
		key_list.sort()
		for k in key_list:
			print '{0} : {1}'.format(k, link[k])
		#print bmgr.ComputeFlow(0x4019b4, func_addr[1])
		#print bmgr.ComputeBranchProcess(func_addr)

	else:
		o_hex.mips()
