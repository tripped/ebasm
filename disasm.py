##
# A quick-and-dirty 65816 disassembler.
#

from array import array

from disassembler import *


#------------------------------------------------------------------------------
# HEURISTIC DISASSEMBLY
#------------------------------------------------------------------------------

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



class Segment(object):
    def __init__(self, ilist):
        self.instructions = ilist
        self.address = (ilist[0].status.pbr << 16) | ilist[0].status.pc

class Subroutine(Segment):
    pass



def recursive_subroutine(container, address, status, entities=dict()):

    if address in entities:
        return entities[address]


def recursive_segment(container, address, status, entities=dict(), seen=dict{}):
    '''Disassembles a segment'''

    if address in entities:
        return entities[address]

    src = iterfrom(container, address)

    instructions = []
    inst = None
    while True:
        inst, status = instruction(src, status)
        instructions.append(inst)

        # JSL long
        if inst.op == 0x22:
            sub,status = recursive_subroutine(container, inst.operand, status, entities)
            entities[inst.operand] = sub
        # JSR short
        elif inst.op == 0x20:
            subadr = makeadr(inst.status.pbr, inst.operand)
            sub,status = recursive_subroutine(container, subadr, status, entities)
            entities[subadr] = sub

        # if it's a JMP instruction, we're done with this segment. In the case
        # of a direct JMP/JML, the caller should continue with a new segment
        # at the new PC.

def recursive_disassemble(container, address, status, entities=dict()):
    '''
        entities = list of all disassembled entities, whether lone instructions
        or subroutines (a subroutine is, for now, just a list of instructions)
    '''

    if address in entities:
        return entities[address]

    src = iterfrom(container, address)

    instructions = []
    inst = None


def bank(address):
    return (address & 0xFF0000) >> 16

def offset(address):
    return address & 0xFFFF

def makeadr(bank, offset):
    return (bank << 16) | offset


# TODO: this should be a parameter
goodbanks = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xEE, 0xEF }

def testwindow(container, start):

    is_code = 0
    not_code = 0

    src = iterfrom(container, start)
    address = start + 0xC00000
    status = Status((address & 0xFF0000) >> 16, address & 0xFFFF, 0, 0)

    instructions = []
    inst = None
    while not inst or inst.op != 0x6b and inst.op != 0x60:
        inst,status = instruction(src, status)

        explanation = ''

        # Check for 'bad' codes
        if inst.op == 0x00:
            not_code += 50  # BRK
            explanation = 'BRK encountered'

        if inst.op == 0x02:
            not_code += 10   # COP
            explanation = 'COP encountered'

        if inst.op in {0x22, 0x5C} and bank(inst.operand) not in goodbanks:
            not_code += 100
            explanation = 'JMP/JSL to non-code bank'

        if inst.op in {0x1C, 0x14, 0x0C, 0x04}:
            not_code += 20
            explanation = 'TRB/TSB encountered'


        # Check for 'good' codes
        if 'const' in instruction_set[inst.op] and \
                      not status.m and \
                      inst.operand < 256:
            is_code += 20
            explanation = 'Likely immediate operand'

        if inst.op in {0x22, 0x5C} and bank(inst.operand) in goodbanks:
            is_code += 10
            explanation = 'JMP/JSL to known code bank'

        if inst.op in {0x6b, 0x60} and instructions[len(instructions)-1].op == 0x2B:
            # PLD followed by RTS or RTL
            is_code += 20
            explanation = 'Return from subroutine sequence'

        print('{:50}{}'.format(disassembly(inst), explanation))
        instructions.append(inst)

    print('testwindow analysis for ${:06X}'.format(address))
    print('is_code confidence:  {}'.format(is_code))
    print('not_code confidence: {}'.format(not_code))


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

    rom = loadfile(filename)

    testwindow(rom, address)

    #src = iterfrom(rom, address)
    #disassemble(src, address + 0xC00000)


