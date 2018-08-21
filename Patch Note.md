# Patch Note


ver 0.10

- add mips assembly

- fix some errors

- modify to copy a register object about branch

- support new operand feature Imm+Imm+Reg (0x30 + var_C+1($sp))

- support new operand feature Imm+Imm (0x30 + var_C+1)


ver 0.9

- fix printing a next line process on all conditional branchs 

- change to use local variables on some instructions

- add the CustomHex object on hex-ray.py


ver 0.8

- add mips assembly(about set)

- support operand feature Addr+Imm (aAddr+1 + 0xC)

- create mips_operand file for object structure


ver 0.7

- refix all branch assemblies

- fix to check ASM_TYPE in all ins + 'i' assemblies

- add a o_reg.get_register method in mult and div assemblies


ver 0.6

- add mips assembly

- fix addiu error about the '$sp' register

- fix mul assembly about 'hi' and 'lo' registers (fault)

- add the '$pc' register

- add to add the '$pc' register on all branch assemblies


ver 0.5

- addition mips assembly (xor, slti)

- fix addiu error about '$sp' register


ver 0.4

- add mips assembly (movz, mult, mfhi, mflo)

- remove type check (mips_asm_set)

- modify return value that is registered by set_register (jal, jalr)

- remove replace (mips_asm_store).

- modify check_var_naming => convert_var_naming, and add check_var_naming method.

- temporarily allow the idc.LocByName's return value that is 0xffffffff in operand.is_expand_operand.


ver 0.3

- view thw assembly calc process

- add method (check_return)

- sort local_var list


ver 0.2

- add mips assembly (bgtz, movn, ext, ins, blez)

- support ascii c string

- support variable name

- fix bug (after perform jump or branch, perform one more the next code)

- etc...


ver.0.1

- add mips assembly (sb, bgez, lbu)

- fix get_register method return value (None => register)

- modify method name (convert_to_var => convert_operand)

- fix convert_operand method return value (string => calculated hex value)

- add method in mips_asmutils.py (have_string, get_string, check_var_naming)

- add conditional to do_addiu, do_sw


ver.0.0
