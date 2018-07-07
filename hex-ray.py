import mipsHex.mips_Iasm as mips_asm
import mipsHex.mips_function as mips_function
import mipsHex.mips_register as mips_register
from mipsHex.mips_asmutils import asmutils

from base.error import *

import idautils
import idc

VERSION = 0.6

'''
get reference list in function
'''
def get_refer_list(start=None, end=None):
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
	func_ref_list = list(set(func_ref_list))

	# Check range between start and end
	for ref in func_ref_list:
		if ref < start or ref >= end:
			func_ref_list.remove(ref)

	return func_ref_list

'''
append a reference address
'''
def append_refer_addr(addr, ref_list, to):
	if addr in ref_list:
		to += NEXTLINE
		to += 'loc_' + hex(addr)[2:-1].upper() + ':'

	return to
'''
append new line
'''
def append_new_line(line, to):
	if line:
		to += NEXTLINE + TAB + line

	return to

'''
main function for mips hex-ray
'''
def hex_ray_mips():
	global NEXTLINE
	global TAB

	# Create a mips function object for hex-ray
	func = mips_function.MIPS_Function()
	reg = mips_register.MIPS_Register()
	asm = mips_asm.MIPS_IAsm()

	# Get current function's name and address using ida python
	func_name, func_addr = func.init_func()
	func_contents = ''

	print "[+] Function name : " + func_name
	print "[+] Function address : " + hex(func_addr[0])

	func_ref_list = get_refer_list(func_addr[0], func_addr[1])

	haslocal = False
	current = func_addr[0]
	while current <= func_addr[1]:
		# Write reference addresses
		func_contents = append_refer_addr(current, func_ref_list, func_contents)

		# assmbly dispatch
		line, n_addr = asm.dispatch(current, reg, func)

		# apply dispatch result
		func_contents = append_new_line(line, func_contents)

		if n_addr:
			current = idc.NextHead(n_addr, func_addr[1])
		else:
			current = idc.NextHead(current, func_addr[1])

	with open(func_name + ".c", "w") as fh:
		fh.write(func.function(func_contents))

if __name__ == '__main__':
	NEXTLINE = '\n'
	TAB = '    '

	hex_ray_mips()
