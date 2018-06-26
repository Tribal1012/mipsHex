# Patch Note

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
