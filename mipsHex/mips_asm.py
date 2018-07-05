# mips_asm.py

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))

from base.asm import *
from mips_asmutils import asmutils

'''
	store mips assembly
	important : mips assmbly type, provide mips assembly utils
'''
class MIPS_Asm(Asm):
	def __init__(self, addr):
		super(MIPS_Asm, self).__init__(addr)

		pass
