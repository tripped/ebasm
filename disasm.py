##
# A quick-and-dirty 65816 disassembler.
#

from array import array
import re


#------------------------------------------------------------------------------
# The definition of the 65816 instruction set.
#------------------------------------------------------------------------------

instruction_set = {
    # ADC
    0x69 : 'ADC #const*', # '*' = actual width of const determined by m bit
    0x6D : 'ADC addr',
    0x6F : 'ADC long',
    0x65 : 'ADC dp',
    0x72 : 'ADC (dp)',
    0x67 : 'ADC [dp]',
    0x7D : 'ADC addr,X',
    0x7F : 'ADC long,X',
    0x79 : 'ADC addr,Y',
    0x75 : 'ADC dp,X',
    0x61 : 'ADC (dp,X)',
    0x71 : 'ADC (dp),Y',
    0x77 : 'ADC [dp],Y',
    0x63 : 'ADC sr,S',
    0x73 : 'ADC (sr,S),Y',

    # AND
    0x29 : 'AND #const*',
    0x2D : 'AND addr',
    0x2F : 'AND long',
    0x25 : 'AND dp',
    0x32 : 'AND (dp)',
    0x27 : 'AND [dp]',
    0x3D : 'AND addr,X',
    0x3F : 'AND long,X',
    0x39 : 'AND addr,Y',
    0x35 : 'AND dp,X',
    0x21 : 'AND (dp,X)',
    0x31 : 'AND (dp),Y',
    0x37 : 'AND [dp],Y',
    0x23 : 'AND sr,S',
    0x33 : 'AND (sr,S),Y',

    # ASL
    0x0A : 'ASL',
    0x0E : 'ASL addr',
    0x06 : 'ASL dp',
    0x1E : 'ASL addr,X',
    0x16 : 'ASL dp,X',

    # Branches
    0x90 : 'BCC near', # PC relative short (1 byte)
    0xB0 : 'BCS near',
    0xF0 : 'BEQ near',
    0xD0 : 'BNE near',
    0x30 : 'BMI near',
    0x10 : 'BPL near',
    0x50 : 'BVC near',
    0x70 : 'BVS near',
    0x80 : 'BRA near',
    0x82 : 'BRL nearx', # PC relative long (2 bytes)

    # BIT
    0x89 : 'BIT #const*',
    0x2C : 'BIT addr',
    0x24 : 'BIT dp',
    0x3C : 'BIT addr,X',
    0x34 : 'BIT dp,X',

    # BRK
    0x00 : 'BRK byte',

    # Status register manipulation
    0x18 : 'CLC',
    0xD8 : 'CLD',
    0x58 : 'CLI',
    0xB8 : 'CLV',
    0x38 : 'SEC',
    0xF8 : 'SED',
    0x78 : 'SEI',

    # CMP
    0xC9 : 'CMP #const*',
    0xCD : 'CMP addr',
    0xCF : 'CMP long',
    0xC5 : 'CMP dp',
    0xD2 : 'CMP (dp)',
    0xC7 : 'CMP [dp]',
    0xDD : 'CMP addr,X',
    0xDF : 'CMP long,X',
    0xD9 : 'CMP addr,Y',
    0xD5 : 'CMP dp,X',
    0xC1 : 'CMP (dp,X)',
    0xD1 : 'CMP (dp),Y',
    0xD7 : 'CMP [dp],Y',
    0xC3 : 'CMP sr,S',
    0xD3 : 'CMP (sr,S),Y',

    # COP
    0x02 : 'COP byte',

    # CPX
    0xE0 : 'CPX #const+',
    0xEC : 'CPX addr',
    0xE4 : 'CPX dp',

    # CPY
    0xC0 : 'CPY #const+',
    0xCC : 'CPY addr',
    0xC4 : 'CPY dp',

    # DEC / DEX / DEY
    0x3A : 'DEA',
    0xCE : 'DEC addr',
    0xC6 : 'DEC dp',
    0xDE : 'DEC addr,X',
    0xD6 : 'DEC dp,X',
    0xCA : 'DEX',
    0x88 : 'DEY',

    # EOR
    0x49 : 'EOR #const*',
    0x4D : 'EOR addr',
    0x4F : 'EOR long',
    0x45 : 'EOR dp',
    0x52 : 'EOR (dp)',
    0x47 : 'EOR [dp]',
    0x5D : 'EOR addr,X',
    0x5F : 'EOR long,X',
    0x59 : 'EOR addr,Y',
    0x55 : 'EOR dp,X',
    0x41 : 'EOR (dp,X)',
    0x51 : 'EOR (dp),Y',
    0x57 : 'EOR [dp],Y',
    0x43 : 'EOR sr,S',
    0x53 : 'EOR (sr,S),Y',

    # INC, INX, INY
    0x1A : 'INA',
    0xEE : 'INC addr',
    0xE6 : 'INC dp',
    0xFE : 'INC addr,X',
    0xF6 : 'INC dp,X',
    0xE8 : 'INX',
    0xC8 : 'INY',

    # JMP / JML
    0x4C : 'JMP addr',
    0x6C : 'JMP (addr)',
    0x7C : 'JMP (addr,X)',
    0x5C : 'JML long',
    0xDC : 'JML [addr]',

    # JSR / JSL
    0x22 : 'JSL long',
    0x20 : 'JSR addr',
    0xFC : 'JSR (addr,X)',

    # LDA
    0xA9 : 'LDA #const*',
    0xAD : 'LDA addr',
    0xAF : 'LDA long',
    0xA5 : 'LDA dp',
    0xB2 : 'LDA (dp)',
    0xA7 : 'LDA [dp]',
    0xBD : 'LDA addr,X',
    0xBF : 'LDA long,X',
    0xB9 : 'LDA addr,Y',
    0xB5 : 'LDA dp,X',
    0xA1 : 'LDA (dp,X)',
    0xB1 : 'LDA (dp),Y',
    0xB7 : 'LDA [dp],Y',
    0xA3 : 'LDA sr,S',
    0xB3 : 'LDA (sr,S),Y',

    # LDX
    0xA2 : 'LDX #const+', # '+' = width depends on x status bit
    0xAE : 'LDX addr',
    0xA6 : 'LDX dp',
    0xBE : 'LDX addr,Y',
    0xB6 : 'LDX dp,Y',

    # LDY
    0xA0 : 'LDY #const+',
    0xAC : 'LDY addr',
    0xA4 : 'LDY dp',
    0xBC : 'LDY addr,X',
    0xB4 : 'LDY dp,X',

    # LSR
    0x4A : 'LSR',
    0x4E : 'LSR addr',
    0x46 : 'LSR dp',
    0x5E : 'LSR addr,X',
    0x56 : 'LSR dp,X',

    # MVN/MVP
    0x54 : 'MVN src,dest',
    0x44 : 'MVP src,dest',

    # NOP
    0xEA : 'NOP',

    # ORA
    0x09 : 'ORA #const*',
    0x0D : 'ORA addr',
    0x0F : 'ORA long',
    0x05 : 'ORA dp',
    0x12 : 'ORA (dp)',
    0x07 : 'ORA [dp]',
    0x1D : 'ORA addr,X',
    0x1F : 'ORA long,X',
    0x19 : 'ORA addr,Y',
    0x15 : 'ORA dp,X',
    0x01 : 'ORA (dp,X)',
    0x11 : 'ORA (dp),Y',
    0x17 : 'ORA [dp],Y',
    0x03 : 'ORA sr,S',
    0x13 : 'ORA (sr,S),Y',

    # PEA / PEI / PER
    0xF4 : 'PEA addr',
    0xD4 : 'PEI (dp)',
    0x62 : 'PER short', # label? see 65816info.txt:1742

    # Push / pull registers
    0x48 : 'PHA',
    0x08 : 'PHP',
    0xDA : 'PHX',
    0x5A : 'PHY',
    0x68 : 'PLA',
    0x28 : 'PLP',
    0xFA : 'PLX',
    0x7A : 'PLY',
    0x8B : 'PHB',
    0x0B : 'PHD',
    0x4B : 'PHK',
    0xAB : 'PLB',
    0x2B : 'PLD',

    # REP
    0xC2 : 'REP #byte',

    # ROL
    0x2A : 'ROL',
    0x2E : 'ROL addr',
    0x26 : 'ROL dp',
    0x3E : 'ROL addr,X',
    0x36 : 'ROL dp,X',

    # ROR
    0x6A : 'ROR',
    0x6E : 'ROR addr',
    0x66 : 'ROR dp',
    0x7E : 'ROR addr,X',
    0x76 : 'ROR dp,X',

    # RTI / RTL / RTS
    0x40 : 'RTI',
    0x6B : 'RTL',
    0x60 : 'RTS',

    # SBC
    0xE9 : 'SBC #const*',
    0xED : 'SBC addr',
    0xEF : 'SBC long',
    0xE5 : 'SBC dp',
    0xF2 : 'SBC (dp)',
    0xE7 : 'SBC [dp]',
    0xFD : 'SBC addr,X',
    0xFF : 'SBC long,X',
    0xF9 : 'SBC addr,Y',
    0xF5 : 'SBC dp,X',
    0xE1 : 'SBC (dp,X)',
    0xF1 : 'SBC (dp),Y',
    0xF7 : 'SBC [dp],Y',
    0xE3 : 'SBC sr,S',
    0xF3 : 'SBC (sr,S),Y',

    # SEP
    0xE2 : 'SEP #byte',

    # STA
    0x8D : 'STA addr',
    0x8F : 'STA long',
    0x85 : 'STA dp',
    0x92 : 'STA (dp)',
    0x87 : 'STA [dp]',
    0x9D : 'STA addr,X',
    0x9F : 'STA long,X',
    0x99 : 'STA addr,Y',
    0x95 : 'STA dp,X',
    0x81 : 'STA (dp,X)',
    0x91 : 'STA (dp),Y',
    0x97 : 'STA [dp],Y',
    0x83 : 'STA sr,S',
    0x93 : 'STA (sr,S),Y',

    # STP
    0xDB : 'STP',

    # STX / STY
    0x8E : 'STX addr',
    0x86 : 'STX dp',
    0x96 : 'STX dp,Y',
    0x8C : 'STY addr',
    0x84 : 'STY dp',
    0x94 : 'STY dp,X',

    # STZ
    0x9C : 'STZ addr',
    0x64 : 'STZ dp',
    0x9E : 'STZ addr,X',
    0x74 : 'STZ dp,X',

    # Register transfers
    0xAA : 'TAX',
    0xA8 : 'TAY',
    0x8A : 'TXA',
    0x98 : 'TYA',
    0xBA : 'TSX',
    0x9A : 'TXS',
    0x9B : 'TXY',
    0xBB : 'TYX',

    # Direct page manipulation
    0x5B : 'TCD',
    0x7B : 'TDC',

    # Stack pointer manipulation
    0x1B : 'TCS',
    0x3B : 'TSC',

    # Test and set/reset memory bits
    0x1C : 'TRB addr',
    0x14 : 'TRB dp',
    0x0C : 'TSB addr',
    0x04 : 'TSB dp',

    # Wait for interrupt
    0xCB : 'WAI',

    # So long and thanks for all the fish
    0x42 : 'WDM',

    # XBA / XCE
    0xEB : 'XBA',
    0xFB : 'XCE',
}

assert(len(instruction_set) == 256)



#------------------------------------------------------------------------------
# Stuff for reading and formatting operands
#------------------------------------------------------------------------------


#
# Functions for reading primitives from a stream. Each returns a tuple
# containing the primitive value and its size in bytes. 
#
def byte(src):
    return next(src), 1

def short(src):
    return (next(src) | (next(src) << 8)), 2

def long(src):
    return (next(src) | (next(src) << 8) | (next(src) << 16)), 3


#
# We need these to treat bytes and shorts as signed integers, e.g. when
# computing absolute targets of relative jumps.
#
def signedbyte(n):
    '''Sign-extends a byte to a signed integer.'''
    return n - 2 * (n & 0x80)

def signedshort(n):
    '''Sign-extends a short to a signed integer.'''
    return n - 2 * (n & 0x8000)


#
# Each type of 65816 operand is processed by a pair of functions: a consumer
# and a stringifier. The consumer reads the correct number of bytes from a
# stream, and the stringifier renders the operand as a string.
#
# Each function takes a status as its second parameter, to handle those operand
# formats that depend on the current status of the CPU.
#
formats = { 'const*', 'const+', 'short', 'byte', 'addr', 'near', 'nearx',
            'long', 'dp', 'sr' }

operand_consumers = {
    'const*': lambda s,p: byte(s) if p.m else short(s),
    'const+': lambda s,p: byte(s) if p.x else short(s),
    'short':  lambda s,p: short(s),
    'byte':   lambda s,p: byte(s),
    'addr':   lambda s,p: short(s),
    'near':   lambda s,p: byte(s),
    'nearx':  lambda s,p: short(s),
    'long':   lambda s,p: long(s),
    'dp':     lambda s,p: byte(s),
    'sr':     lambda s,p: byte(s)
}

operand_stringifiers = {
    'const*': lambda n,p: '${:0{w}X}'.format(n, w = 2 if p.m else 4),
    'const+': lambda n,p: '${:0{w}X}'.format(n, w = 2 if p.x else 4),
    'short':  '${:04X}'.format,
    'byte':   '${:02X}'.format,
    'addr':   '${:04X}'.format,
    'near':   lambda n,p: '${:04X}'.format(p.pc + 2 + signedbyte(n)),
    'nearx':  lambda n,p: '${:04X}'.format(p.pc + 3 + signedshort(n)),
    'long':   '${:06X}'.format,
    'dp':     '${:02X}'.format,
    'sr':     '{}'.format
}

#
# Build a regexp for finding operand types in a string. We sort the keys in
# order of descending length to avoid missing a longer key by finding a short
# key first, e.g., "BRL nearx" matches "near" before it matches "nearx".
#
pattern = re.compile(
        '|'.join(map(re.escape, sorted(formats, key=len, reverse=True)))
    )


def makereader(description):
    '''Makes a reader function for the specified opcode, e.g.,

            f = makereader('LDX #const+')

       The returned function can be applied to a byte stream and a status
       object to pull a correctly-sized operand from the stream; for example,
       f(src, Status(x=1,...)) will read only one byte from src, because the
       LDX #const+ instruction matches the size of the CPU's X register.'''

    match = pattern.search(description)
    if match:
        return operand_consumers[match.group(0)]
    else:
        return lambda *args: None


def makestringifier(description):
    '''Makes a stringifier function for the specified opcode, e.g.,

            f = makestringifier('LDX #const+')
    
       The returned function can be applied to an operand value and a status
       object to get an assembly language representation of the instruction,
       e.g.,  f(32, Status(x=1,...))  will return "LDX #$20" '''

    match = pattern.search(description)

    if not match:
        return lambda *args: description

    stringifier = operand_stringifiers[match.group(0)]
    description = pattern.sub('{}', description)

    return lambda n,s: description.format(stringifier(n, s))


#
# Make a reader and stringifier for every opcode in the 65816 instruction set
#
readers = { k : makereader(v) for k,v in instruction_set.items() }
stringifiers = { k : makestringifier(v) for k,v in instruction_set.items() }




#------------------------------------------------------------------------------
# 
# 
#
#------------------------------------------------------------------------------



from collections import namedtuple

#
# Status represents the state of the 65816 at a particular point in time. It
# consists of the values of the program counter register and the m and x bits
# from the CPU status register.
#
Status = namedtuple('Status', ['pbr', 'pc', 'm', 'x'])


class Instruction(object):
    '''An instruction is an instance of a 65816 machine instruction, including
       the machine opcode, its operand, and the status of the CPU at that point
       in the program.'''

    def __init__(self, op, operand, status):
        self.op = op
        if operand:
            self.operand = operand[0]
            self.operand_len = operand[1]
        else:
            self.operand = 0
            self.operand_len = 0
        self.status = status

    def __len__(self):
        return 1 + self.operand_len

    def __iter__(self):
        '''Iterates over the raw bytes of the instruction.'''
        yield self.op
        for i in range(self.operand_len):
            yield (self.operand >> i*8) & 0xFF

    def __str__(self):
        '''Returns the instruction as an assembly language string.'''
        return stringifiers[self.op](self.operand, self.status)




def disassembly(inst, address=True, machine=True, status=True):
    '''Returns a string representation of the disassembly of an instruction.
        @param inst The instruction to disassemble
        @param address If true, the instruction's address will be included
        @param machine If true, the raw machine code will be included'''

    result = '' 

    if address:
        result += '{:02X}/{:04X}: '.format(inst.status.pbr, inst.status.pc)
    if machine:
        result += '{:13}'.format(' '.join(map('{:02X}'.format, inst)))
    
    result += '{:20}'.format(str(inst))

    if status:
        result += '{} {}'.format('-M-' if inst.status.m else '---',
                                '-X-' if inst.status.x else '---')

    return result

#
# This is horrible, but getting slightly better
#

def instruction(src, status):
    '''Reads a single instruction from a stream and returns a pair (inst, stat)
       where inst is an object representing the instruction, and stat is the
       'successor' status of the instruction, i.e. the state of the CPU after
       executing the instruction.

        @param src An iterable byte stream from which to read the instruction
        @param status An object recording state of the 65816 at the place in
                 the program where the instruction occurs; must include m, x
                 flags and pc register value.'''

    # Get the opcode and its operand
    op = next(src)
    operand = readers[op](src, status)

    # Determine new values of m and x flags
    m = status.m
    x = status.x

    # SEP and REP modify status bits directly
    if op == 0xE2:  # SEP
        if operand[0] & 0x20: m = 1
        if operand[0] & 0x10: x = 1
    elif op == 0xC2:  # REP
        if operand[0] & 0x20: m = 0
        if operand[0] & 0x10: x = 0
    # Subroutine jumps are assumed to reset status bits
    elif op in {0x22, 0x20, 0xFC}:
        m = 0
        x = 0

    # Now we have enough information to compute the successor status. It'll go
    # like this:
    #  - First, the program counter of the successor is incremented
    #     - successor.pc = status.pc + 1 + len(operand)
    #  - Then we compute the new status of m and x flags:
    #     - If the op is SEP or REP, the status change is computed from
    #       its operand
    #     - If the op is a JSL/JSR, we can do one of two things:
    #        1. Assume that it resets m and x to 0. This is probably a good
    #           assumption in most cases.
    #        2. Examine the function being jumped to, if necessary reading
    #           and disassembling it first, to see if it changes m or x.
    #           Determining this in general is of course impossible, but we
    #           could probably make some good guesses.
    #     - In all other cases, m and x are unchanged.
    #        

    inst = Instruction(op, operand, status)
    newstatus = Status(
            pbr = status.pbr,
            pc = status.pc + len(inst),
            m = m,
            x = x)

    return (inst, newstatus)


def subroutine(src, status):
    '''Reads a subroutine from src, reading instructions sequentially until an
       RTL (0x6B) or RTS (0x60) opcode is reached. Returns pair (func,status),
       where func is an object representing the subroutine and status is the
       expected state of the CPU on return from the subroutine.'''

    instructions = []

    inst = None
    while not inst or inst.op != 0x6b and inst.op != 0x60:
        inst,status = instruction(src, status)
        instructions.append(inst)

    return (instructions, status)
    

def disassemble(src, base):

    # Initialize status
    status = Status((base & 0xFF0000) >> 16, base & 0xFFFF, 0, 0)

    instructions,status = subroutine(src, status)

    for i in instructions:
        print(disassembly(i))


def loadfile(filename):
    f = open(filename, mode='rb')
    return array('B', f.read())


def iterfrom(container, offset):
    while True:
        try:
            offset += 1
            yield container[offset - 1]
        except IndexError:
            raise StopIteration()


if __name__ == '__main__':

    import sys
    if len(sys.argv) < 3:
        print('''Usage:
    disasm.py <romfile> <hexoffset>''')
        exit(1)

    filename = sys.argv[1]
    address = int(sys.argv[2], 16)

    src = iterfrom(loadfile(filename), address)

    disassemble(src, address + 0xC00000)


