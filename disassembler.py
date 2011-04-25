#
# Disassembler core
#
# Defines the functions for reading and expressing disassembly primitives, i.e.
# opcodes and their operands.
#

import re


from instructionset import * 

from collections import namedtuple

#------------------------------------------------------------------------------
# Stuff for reading and formatting operands
#------------------------------------------------------------------------------

Operand = namedtuple('Operand', ['value', 'len'])
Operand.__len__ = lambda self: self.len
Operand.__int__ = lambda self: self.value

#
# Functions for reading primitives from a stream. Each returns a tuple
# containing the primitive value and its size in bytes. 
#
def byte(src):
    return Operand(next(src), 1)

def short(src):
    return Operand((next(src) | (next(src) << 8)), 2)

def long(src):
    return Operand((next(src) | (next(src) << 8) | (next(src) << 16)), 3)


#
# We need these to treat bytes and shorts as signed integers, e.g. when
# computing absolute targets of relative jumps.
#
def signedbyte(n):
    '''Sign-extends a byte to a signed integer.'''
    return (int(n) ^ 0x80) - 0x80

def signedshort(n):
    '''Sign-extends a short to a signed integer.'''
    return (int(n) ^ 0x8000) - 0x8000


#
# Each type of 65816 operand is processed by a pair of functions: a consumer
# and a stringifier. The consumer reads the correct number of bytes from a
# stream, and the stringifier renders the operand as a string.
#
# Each function takes a status as its second parameter, to handle those operand
# formats that depend on the current status of the CPU.
#
formats = { 'const*', 'const+', 'short', 'byte', 'addr', 'near', 'nearx',
            'long', 'dp', 'sr', 'src,dst' }

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
    'sr':     lambda s,p: byte(s),
    'src,dst':lambda s,p: short(s)
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
    'sr':     '{}'.format,
    'src,dst':lambda n,p: '${:02X},${:02X}'.format((n & 0xFF), (n & 0xFF00) >> 8)
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

       If the instruction read was a branch instruction other than BRA or BRL,
       status is a tuple consisting of the successor status for both possible
       paths of the branch.

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

    # TODO: Also compute c and e bits, since the e (emulation) bit forces all
    # registers to 8 bits as well.
    '''
    c = status.c
    e = status.e
    if op == CLC:
        c = 0
    elif op == SEC:
        c = 1
    elif op in { ops that change c }:
        c = Unknown
    elif op == XCE:
        c,e = e,c
    '''

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

    if isbranch(op):
        
        pc = status.pc + signedbyte(operand)

    newstatus = Status(
            pbr = status.pbr,
            pc = status.pc + len(inst),
            m = m,
            x = x)

    return (inst, newstatus)
