# ----------------------------------------------------------------------
# Holtek HT1130 processor module
# Copyright (c) 2023 Ilya Kurdyukov
#
# Compatible with IDA 7.x and possibly later versions.

import sys
from ida_idp import *
from ida_ua import *
from ida_lines import *
from ida_problems import *
from ida_xref import *
from ida_idaapi import *
from ida_bytes import *

if sys.version_info.major < 3:
  range = xrange

# sign extend b low bits in x
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    return (x & (m - 1)) - (x & m)

# treat unused non-zero bits as an error
CHECK_UNUSED = 1

# ----------------------------------------------------------------------
class ht1130_processor_t(processor_t):
    """
    Processor module classes must derive from processor_t
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1130

    # Processor features
    flag = PR_SEGS | PR_USE32 | PR_DEFSEG32 | PR_RNAMESOK | PRN_HEX

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["ht1130"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["Holtek HT1130"]

    # size of a segment register in bytes
    segreg_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 0, 0, 0)


    # only one assembler is supported
    assembler = {
        # flag
        "flag": ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        "uflag": 0,

        # Assembler name (displayed in menus)
        "name": "Holtek HT1130 assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        # 'header': [".ht1130"],

        # org directive
        "origin": ".org",

        # end directive
        "end": ".end",

        # comment string (see also cmnt2)
        "cmnt": "#",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        "accsep": "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".char",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".half",

        # remove if not allowed
        'a_dword': ".word",

        # remove if not allowed
        'a_qword': ".dword",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': ".space %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': ".",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': ".extern",

        # "comm" (communal variable)
        "a_comdef": "",

        # "align" keyword
        "a_align": ".align",

        # Left and right braces used in complex expressions
        "lbrace": "(",
        "rbrace": ")",

        # %  mod     assembler time operation
        "a_mod": "%",

        # &  bit and assembler time operation
        "a_band": "&",

        # |  bit or  assembler time operation
        "a_bor": "|",

        # ^  bit xor assembler time operation
        "a_xor": "^",

        # ~  bit not assembler time operation
        "a_bnot": "~",

        # << shift left assembler time operation
        "a_shl": "<<",

        # >> shift right assembler time operation
        "a_shr": ">>",

        # size of type (format string) (optional)
        "a_sizeof_fmt": "size %s",

        'flag2': 0,

        # the include directive (format string) (optional)
        'a_include_fmt': '.include "%s"',
    }

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt']

    # ----------------------------------------------------------------------

    maptbl_all = [
        # 0x00
        'rr',  'rl',  'rrc', 'rlc', 'mov', 'mov', 'mov', 'mov',
        'adc', 'add', 'sbc', 'sub', 'inc', 'dec', 'inc', 'dec',
        # 0x10
        'inc', 'dec', 'inc', 'dec', 'inc', 'dec', 'inc', 'dec',
        'inc', 'dec', 'and', 'xor', 'or',  'and', 'xor', 'or',
        # 0x20
        'mov', 'mov', 'mov', 'mov', 'mov', 'mov', 'mov', 'mov',
        'mov', 'mov', 'clc', 'stc', 'ei',  'di',  'ret', 'reti',
        # 0x30
        'out', 'inc', 'in', 'in', 'in', '', 'daa', 'halt',
        'timer', 'timer', 'mov', 'mov', 'mov', 'mov', 'nop', 'dec',
        # 0x40
        'add', 'sub', 'and', 'xor', 'or', 'sound', 'mov', 'timer',
        'sound', 'sound', 'sound', 'sound', 'read', 'readf', 'read', 'readf',
    ]
    # magic like *(['mov'] * 48) only works in python3
    maptbl_rep = [
        ['mov', 48], # 0x50
        ['ja0', 8], ['ja1', 8], ['ja2', 8], ['ja3', 8], # 0x80
        ['jnz', 16], ['jz', 8], ['jnz', 8], # 0xa0
        ['jc', 8], ['jnc', 8], # 0xc0
        ['jtmr', 8], ['jnz', 8], # 0xd0
        ['jmp', 16], ['call', 16] # 0xe0
    ]

    def notify_ana(self, insn):
        """
        Decodes an instruction into 'insn'.
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        opc = insn.get_next_byte() & 0xff

        if opc == 0x35: # undefined instructon
            return 0

        insn.itype = self.maptbl_all[opc]

        if opc < 0x04:
            insn.Op1.type = o_reg
            insn.Op1.reg = self.ireg_a
 
        elif opc < 0x08:
            reg = self.ireg_r1r0 + (opc >> 1 & 1)
            if opc & 1 == 0:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_a
                insn.Op2.type = o_displ
                insn.Op2.reg = reg
            else:
                insn.Op1.type = o_displ
                insn.Op1.reg = reg
                insn.Op2.type = o_reg
                insn.Op2.reg = self.ireg_a

        elif opc < 0x0c:
            insn.Op1.type = o_reg
            insn.Op1.reg = self.ireg_a
            insn.Op2.type = o_displ
            insn.Op2.reg = self.ireg_r1r0

        elif opc < 0x10:
            reg = self.ireg_r1r0 + (opc >> 1 & 1)
            insn.Op1.type = o_displ
            insn.Op1.reg = reg

        elif opc < 0x1a:
            reg = self.ireg_r0 + (opc >> 1 & 7)
            insn.Op1.type = o_reg
            insn.Op1.reg = reg

        elif opc < 0x20:
            if opc < 0x1d:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_a
                insn.Op2.type = o_displ
                insn.Op2.reg = self.ireg_r1r0
            else:
                insn.Op1.type = o_displ
                insn.Op1.reg = self.ireg_r1r0
                insn.Op2.type = o_reg
                insn.Op2.reg = self.ireg_a

        elif opc < 0x2a:
            reg = self.ireg_r0 + (opc >> 1 & 7)
            insn.Op1.type = o_reg
            insn.Op2.type = o_reg
            if opc & 1 == 0:
                insn.Op1.reg = reg
                insn.Op2.reg = self.ireg_a
            else:
                insn.Op1.reg = self.ireg_a
                insn.Op2.reg = reg

        elif opc < 0x30:
            pass

        elif opc < 0x40:
            if opc == 0x30:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_pa
                insn.Op2.type = o_reg
                insn.Op2.reg = self.ireg_a
            elif opc == 0x31:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_a
            elif opc < 0x35:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_a
                insn.Op2.type = o_reg
                insn.Op2.reg = self.ireg_pm + opc - 0x32
            elif opc < 0x38:
                pass
            elif opc < 0x3a:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_on + (opc & 1)
            elif opc < 0x3e:
                insn.Op1.type = o_reg
                insn.Op2.type = o_reg
                if opc < 0x3c:
                    insn.Op1.reg = self.ireg_a
                    insn.Op2.reg = self.ireg_tmrl + (opc & 1)
                else:
                    insn.Op1.reg = self.ireg_tmrl + (opc & 1)
                    insn.Op2.reg = self.ireg_a

            elif opc == 0x3f:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_a

        elif opc < 0x48:
            opc2 = insn.get_next_byte()
            if CHECK_UNUSED and opc != 0x47 and opc2 & 0xf0:
                return 0
            if opc < 0x45:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_a
                insn.Op2.type = o_imm
                insn.Op2.value = opc2 & 0xf
            elif opc == 0x45:
                insn.Op1.type = o_imm
                insn.Op1.value = opc2 & 0xf
            elif opc == 0x46:
                insn.Op1.type = o_reg
                insn.Op1.reg = self.ireg_r4
                insn.Op2.type = o_imm
                insn.Op2.value = opc2 & 0xf
            elif opc == 0x47:
                insn.Op1.type = o_imm
                insn.Op1.value = opc2 & 0xff

        elif opc < 0x50:
            insn.Op1.type = o_reg
            insn.Op1.reg = self.maptbl_48reg[opc & 7]

        # 0x50
        elif opc < 0x70:
            reg = self.ireg_r1r0 + (opc >> 4) - 5
            opc2 = insn.get_next_byte()
            if CHECK_UNUSED and opc2 & 0xf0:
                return 0
            insn.Op1.type = o_reg
            insn.Op1.reg = reg
            insn.Op2.type = o_imm
            insn.Op2.value = (opc & 0xf) | (opc2 & 0xf) << 4

        elif opc < 0x80:
            insn.Op1.type = o_reg
            insn.Op1.reg = self.ireg_a
            insn.Op2.type = o_imm
            insn.Op2.value = opc & 0xf

        # 0x80
        elif opc < 0xe0:
            addr = (insn.ea & 0x800) | (opc & 7) << 8
            addr |= insn.get_next_byte() & 0xff
            if 0x070f0000 >> (opc >> 3) & 1:
                insn.Op1.type = o_near
                insn.Op1.addr = addr
            else:
                insn.Op1.type = o_reg
                if opc < 0xb0:
                    insn.Op1.reg = self.ireg_r0 + (opc >> 3 & 1)
                elif opc < 0xc0:
                    insn.Op1.reg = self.ireg_a
                else: # 0xd8
                    insn.Op1.reg = self.ireg_r4
                insn.Op2.type = o_near
                insn.Op2.addr = addr

        # 0xe0
        else:
            addr = (opc & 0xf) << 8
            addr |= insn.get_next_byte() & 0xff
            insn.Op1.type = o_near
            insn.Op1.addr = addr

        return insn.size

    # ----------------------------------------------------------------------
    def handle_operand(self, insn, op, dref_flag):
        if op.type == o_near:
            if insn.get_canon_feature() & CF_CALL:
                insn.add_cref(op.addr, 0, fl_CN)
            else:
                insn.add_cref(op.addr, 0, fl_JN)

    def notify_emu(self, insn):
        Feature = insn.get_canon_feature()

        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, dr_R)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, dr_W)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, dr_R)
        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        flow = Feature & CF_STOP == 0
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True

    # ----------------------------------------------------------------------
    def notify_out_operand(self, ctx, op):
        optype = op.type

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            ctx.out_value(op, OOFW_32 | OOF_SIGNED)
        elif optype == o_near:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_long(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_displ:
            ctx.out_symbol('[')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(']')
        else:
            return False

        return True

    # ----------------------------------------------------------------------
    def out_mnem(self, ctx):
        ctx.out_mnem(8, "")
        return 1

    # ----------------------------------------------------------------------
    def notify_out_insn(self, ctx):
        ctx.out_mnemonic()

        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)
        for i in range(1, 2):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    # ----------------------------------------------------------------------

    # Array of instructions
    instruc = [
        {'name': '', 'feature': 0, 'cmt': 'bad opcode'},

        {'name': 'rr',    'feature': CF_CHG1, 'cmt': 'rotate A right'},
        {'name': 'rl',    'feature': CF_CHG1, 'cmt': 'rotate A left'},
        {'name': 'rrc',   'feature': CF_CHG1, 'cmt': 'rotate A right through carry'},
        {'name': 'rlc',   'feature': CF_CHG1, 'cmt': 'rotate A left through carry'},
        {'name': 'mov',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'move'},
        {'name': 'adc',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'add with carry'},
        {'name': 'add',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'add'},
        {'name': 'sbc',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'subtract with borrow'},
        {'name': 'sub',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'subtract'},
        {'name': 'inc',   'feature': CF_CHG1, 'cmt': 'increment'},
        {'name': 'dec',   'feature': CF_CHG1, 'cmt': 'decrement'},

        {'name': 'and',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'bitwise and'},
        {'name': 'xor',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'bitwise exclusive or'},
        {'name': 'or',    'feature': CF_CHG1 | CF_USE2, 'cmt': 'bitwise or'},

        {'name': 'clc',   'feature': 0, 'cmt': 'clear carry'},
        {'name': 'stc',   'feature': 0, 'cmt': 'set carry'},
        {'name': 'ei',    'feature': 0, 'cmt': 'enable interrupts'},
        {'name': 'di',    'feature': 0, 'cmt': 'disable interrupts' },

        {'name': 'ret',   'feature': CF_STOP, 'cmt': 'return from subroutine'},
        {'name': 'reti',  'feature': CF_STOP, 'cmt': 'return from interrupt'},

        {'name': 'out',   'feature': CF_USE1 | CF_USE2, 'cmt': 'output ACC to port'},
        {'name': 'in',    'feature': CF_CHG1 | CF_USE2, 'cmt': 'input port to ACC'},
        {'name': 'daa',   'feature': 0, 'cmt': 'decimal adjust accumulator'},
        {'name': 'halt',  'feature': 0, 'cmt': 'enter power down mode'},
        {'name': 'nop',   'feature': 0, 'cmt': 'no operation'},

        {'name': 'timer', 'feature': CF_USE1 },
        {'name': 'sound', 'feature': CF_USE1 },
        # read/readf order is important
        {'name': 'read',  'feature': CF_CHG1, 'cmt': 'm[r1r0]:a = rom[pc>>8:a:r4]'},
        {'name': 'read',  'feature': CF_CHG1, 'cmt': 'r4:a = rom[pc>>8:a:m[r1r0]]'},
        {'name': 'readf', 'feature': CF_CHG1, 'cmt': 'm[r1r0]:a = rom[0xf:a:r4]'},
        {'name': 'readf', 'feature': CF_CHG1, 'cmt': 'r4:a = rom[0xf:a:m[r1r0]]'},

        {'name': 'ja0',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if A & 1'},
        {'name': 'ja1',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if A & 2'},
        {'name': 'ja2',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if A & 4'},
        {'name': 'ja3',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if A & 8'},
        {'name': 'jz',    'feature': CF_USE1 | CF_USE2 | CF_JUMP, 'cmt': 'jump if zero'},
        {'name': 'jnz',   'feature': CF_USE1 | CF_USE2 | CF_JUMP, 'cmt': 'jump if not zero'},
        {'name': 'jc',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if carry is set'},
        {'name': 'jnc',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if carry is clear'},
        {'name': 'jtmr',  'feature': CF_USE1 | CF_JUMP, 'cmt': 'jump if timer overflow'},
        {'name': 'jmp',   'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': 'jump unconditionally'},
        {'name': 'call',  'feature': CF_USE1 | CF_CALL, 'cmt': 'call subroutine'},
    ]

    # icode of the first instruction
    instruc_start = 0

    def maptbl_icode(self, tab):
        for i, s in enumerate(tab):
            tab[i] = self.name2icode[s]

    def init_instructions(self):

        for i in range(len(self.reg_names)):
            setattr(self, 'ireg_' + self.reg_names[i], i)

        self.name2icode = {}
        for i, x in enumerate(self.instruc):
            self.name2icode[x['name']] = i

        # icode of the last instruction + 1
        self.instruc_end = len(self.instruc)

        for x, n in self.maptbl_rep:
            for i in range(n):
                self.maptbl_all.append(x)

        self.maptbl_icode(self.maptbl_all)

        # fix read/readf comment
        self.maptbl_all[0x4e] -= 1
        self.maptbl_all[0x4f] -= 1

        self.maptbl_48reg = [
            self.ireg_one, self.ireg_loop, self.ireg_off, self.ireg_a,
            self.ireg_r4a, self.ireg_r4a, self.ireg_mr0a, self.ireg_mr0a
        ]

    # ----------------------------------------------------------------------

    # Registers definition
    reg_names = [
        # General purpose registers
        "a", "r0", "r1", "r2", "r3", "r4", "r1r0", "r3r2",

        # Special names
        "pa", "pm", "ps", "pp", "tmrl", "tmrh",
        "on", "off", "one", "loop", "r4a", "mr0a",

        # Fake segment registers
        "CS", "DS"
    ]

    def init_registers(self):
        # number of CS register
        self.reg_code_sreg = self.reg_names.index("CS")

        # number of DS register
        self.reg_data_sreg = self.reg_names.index("DS")

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.reg_code_sreg
        self.reg_last_sreg  = self.reg_data_sreg

    # ----------------------------------------------------------------------
    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from processor_t
def PROCESSOR_ENTRY():
    return ht1130_processor_t()
