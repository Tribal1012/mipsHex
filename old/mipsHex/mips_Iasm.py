# mips_asm.py

from asm_type.all import *

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from base.Iasm import *

import idc

'''
	mips assembly interface
	__init__ : define a dictionary about mips assembly type
	dispatch : call method based on specific mips assembly type
'''
class MIPS_IAsm(IAsm):
	def __init__(self):
		super(MIPS_IAsm, self).__init__()

		self.mips_asm_class = {
			'store':mips_store.MIPS_Asm_Store,
			'load':mips_load.MIPS_Asm_Load,
			'move':mips_move.MIPS_Asm_Move,
			'branch':mips_branch.MIPS_Asm_Branch,
			'set':mips_set.MIPS_Asm_Set,
			'jump':mips_jump.MIPS_Asm_Jump,
			'arithmetic':mips_arith.MIPS_Asm_Arithmetic,
			'bits':mips_bits.MIPS_Asm_Bits,
			'shift':mips_shift.MIPS_Asm_Shift,
			'etc':mips_etc.MIPS_Asm_Etc
		}

	# Find instruction type and call 'do_(instruction)' method
	def dispatch(self, addr, o_reg, o_func):
		ins = idc.GetMnem(addr)

		class_list = self.mips_asm_class.values()
		for obj in class_list:
			method = 'do_' + ins
			if hasattr(obj, method):
				if self.mips_asm_class['branch'] == obj:
					dispatch_cmd = getattr(self, 'dispatch')
					asm_obj = obj(addr, dispatch_cmd, o_reg, o_func)
					command = getattr(asm_obj, method)
				elif self.mips_asm_class['jump'] == obj:
					dispatch_cmd = getattr(self, 'dispatch')
					asm_obj = obj(addr, dispatch_cmd, o_reg, o_func)
					command = getattr(asm_obj, method)
				else:
					asm_obj = obj(addr)
					command = getattr(asm_obj, method)

				return command(o_reg, o_func)

		error("[-] current({0}), Not defined instruction".format(hex(addr)))
