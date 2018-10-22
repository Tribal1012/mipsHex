'''
	cpu architectures
'''
ARCHITECTURE = {
	'MIPS':0x0
}

'''
	assembly type
	number is defined in IDA
'''
ASM_TYPE = {
	'Bad_Opnd':-1,
	'None':0,
	'Gen_Reg':1,
	'Mem_Ref':2,
	'Base_Idx':3,
	'Base_Idx_Disp':4,
	'Imm':5,
	'Imm_Far_Addr':6,
	'Imm_Near_Addr':7,
	'PC_386_Trace':8,
	'PC_386_Debug':9,
	'PC_386_Control':10,
	'PC_FPP':11,
	'PC_MMX':12,
	'8051_Bit1':8,
	'8051_Bit2':9,
	'8051_Bit3':10,
	'80196_Intmem':8,
	'80196_Intmem_P':9,
	'80196_Offset_Intmem':10,
	'80196_Bit':11,
	'ARM_Shift':8,
	'ARM_MLA':9,
	'ARM_Reg_List':10,
	'ARM_Cop_Reg_List':11,
	'ARM_Cop_Reg':12,
	'PPC_SPR':8,
	'PPC_2_FPR':9,
	'PPC_SH_MB_ME':10,
	'PPC_CR_Field':11,
	'PPC_CR_Bit':12,
	'TMS320C5_Bit':8,
	'TMS320C5_Bit_Not':9,
	'TMS320C5_Condition':10,
	'TMS320C6_Reg_Pair':8,
	'Z8_Intmem':8,
	'Z8_Rx':9,
	'Z80_Condition':8
}

OPND_FEATURE = {
	'None':0,					# Reserved
	'Reg':1,					# e.g) $a0
	'Reg_Imm':2,				# e.g) 0xC($a0)
	'Imm':3,					# e.g) 0xC
	'Imm_Imm':4,				# e.g) 0x30+var_C
	'Imm_Imm_Reg':5,			# e.g) 0x30+var_C($sp)
	'Addr':6,					# e.g) aAddr
	'Addr_Imm':7,				# e.g) (aAddr - 0xC)
	'Addr_Imm_Reg':8,			# e.g) (aAddr - 0xC)($a0)
	'Addr_Offset_Imm_Reg':9		# e.g) (aAddr+0xC - 0xC)($a0)
}
