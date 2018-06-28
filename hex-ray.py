import mipsHex.mips_Iasm as mips_asm
import mipsHex.mips_function as mips_function
import mipsHex.mips_register as mips_register
from mipsHex.mips_asmutils import asmutils

from base.error import *

import idautils
import idc

VERSION = 0.3

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

	# Skip prologue and create local variable that stored previous registers
	haslocal = False
	current = func_addr[0]
	total_stack_size = 0
	while current <= func_addr[1]:
		if not haslocal:
			ins = idc.GetMnem(current)
			opr1 = idc.GetOpnd(current, 0)
			opr2 = idc.GetOpnd(current, 1)

			if ins == 'sw':
				if opr1 == '$ra':
					try:
						func.set_local_var('ret', opr1)
					except:
						print "[-] Not found total_stack_size!"
				elif reg.issaved(opr1):
					try:
						var_name = asmutils.convert_operand(opr2)
						func.set_local_var(var_name, opr1)
					except:
						print "[-] Not found total_stack_size!!"
				else:
					haslocal = True
			elif ins == 'addiu':
				if opr1 == '$sp':
					total_stack_size = int(opr2, 16)
				else:
					haslocal = True
			elif ins == 'li':
				if opr1 == '$gp':
					asm.dispatch(current, reg, func)
			elif ins == 'addu':
				if opr1 == '$gp':
					asm.dispatch(current, reg, func)
			else:
				if not haslocal:
					haslocal = True

				continue

			current = idc.NextHead(current, func_addr[1])
			continue

		# Write reference addresses
		if current in func_ref_list:
			func_contents += NEXTLINE
			func_contents += 'loc_' + hex(current)[2:-1].upper() + ':'

		line, n_addr = asm.dispatch(current, reg, func)

		if line is not None:
			line = NEXTLINE + TAB + line
			func_contents += line

		if n_addr is None:
			current = idc.NextHead(current, func_addr[1])
		else:
			current = idc.NextHead(n_addr, func_addr[1])

	with open(func_name + ".c", "w") as fh:
		fh.write(func.function(func_contents))

if __name__ == '__main__':
	NEXTLINE = '\n'
	TAB = '    '

	hex_ray_mips()