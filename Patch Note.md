# Patch Note

ver 0.5

- addition mips assembly (xor, slti)

- fix addiu error about '$sp' register


ver 0.4

- addition mips assembly (movz, mult, mfhi, mflo)

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

- addition mips assembly (bgtz, movn, ext, ins, blez)

- support ascii c string

- support variable name

- fix bug (after perform jump or branch, perform one more the next code)

- etc...


ver.0.1

- addition mips assembly (sb, bgez, lbu)

- fix get_register method return value (None => register)

- modify method name (convert_to_var => convert_operand)

- fix convert_operand method return value (string => calculated hex value)

- addition method in mips_asmutils.py (have_string, get_string, check_var_naming)

- addition conditional to do_addiu, do_sw


ver.0.0
