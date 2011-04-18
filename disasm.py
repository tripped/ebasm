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
    

def disassemble(src, base, flags=0):
    # Initialize status
    status = Status((base & 0xFF0000) >> 16, base & 0xFFFF, flags, flags)
    instructions,status = subroutine(src, status)
    for i in instructions:
        print(disassembly(i))


class Subroutine(object):
    def __init__(self, address):
        self.instructions = []
        self.address = address
        self.exitstatus = None
    
    def append(self, inst):
        self.instructions.append(inst)


def recursive_subroutine(container, address, status, entities):

    address = snesoffset(address)

    if address in entities:
        if not isinstance(entities[address], Subroutine):
            print("Warning: attempted to recurse into non-subroutine")
        return entities[address]

    print('Found new subroutine at ${:06X}'.format(address))

    src = iterfrom(container, fileoffset(address))
    status = Status(bank(address), offset(address), status.m, status.x)

    # Register a subroutine in the entities table first, just in case we get
    # here again through recursion
    sub = Subroutine(address)
    entities[address] = sub

    inst = None
    while not inst or inst.op != 0x60 and inst.op != 0x6B:
        inst,status = instruction(src, status)
        sub.append(inst)

        if inst.op == 0x22:
            print(disassembly(inst))
            recursive_subroutine(container, inst.operand, status, entities)
        elif inst.op == 0x20:
            print(disassembly(inst))
            subadr = makeadr(inst.status.pbr, inst.operand)
            recursive_subroutine(container, subadr, status, entities)

    #sub.exitstatus = status
    # ohsnap! so, we set exit status here at the end... but the exitstatus of
    # the subroutine object is None until this point, and we _might_ get back to
    # this subroutine through mutual recursion.... in which case whatever gets
    # there will see a 'None' status!
    #
    # Um, quickfix for this is to offer the entry status as a best guess for the
    # exit status? That doesn't make much sense though.
    #
    # Better solution for now: don't use the exit status from subroutines.
    #
    # Additionally, we need to start being careful about status.pbr and status.pc;
    # the ending status of this function will be the successor of an RTS or RTL,
    # which of course isn't known statically for pbr and pc. Those fields should
    # be marked with an "Unknown" value, preferably. That way if we screw up and
    # let Unknown pbr and pc values propagate to other disassemblies, it will be
    # obvious what has happened, as opposed to merely seeing wrong program counter
    # values.
    return sub



def recursive_disassemble(container, address, status):
    '''Disassembles a segment of code, recursively following subroutine calls.
       The 'top' level of code is only followed until the first untraceable
       jump, i.e., any indirect jump or RTS/RTL.'''

    src = iterfrom(container, fileoffset(address))
    entities = dict()
    while True:
        inst, status = instruction(src, status)
        entities[makeadr(inst.status.pbr, inst.status.pc)] = inst

        # JSL long
        if inst.op == 0x22:
            recursive_subroutine(container, inst.operand, status, entities)
        # JSR short
        elif inst.op == 0x20:
            subadr = makeadr(inst.status.pbr, inst.operand)
            recursive_subroutine(container, subadr, status, entities)
        # Untraceable indirect jumps
        elif inst.op in { 0x6C, 0x7C, 0xDC, 0xFC }:
            print("Warning: untraceable jump")
            break
        # Subroutine return
        elif inst.op in { 0x60, 0x6B }:
            break

        # Traceable jumps
        elif inst.op in { 0x4C, 0x5C }:
            if inst.op == 0x4C:
                newadr = makeadr(inst.status.pbr, inst.operand)
            else:
                newadr = inst.operand

            src = iterfrom(container, fileoffset(newadr))
            status = Status(bank(newadr), offset(newadr), status.m, status.x)

    return entities, status


def bank(address):
    return (address & 0xFF0000) >> 16

def offset(address):
    return address & 0xFFFF

def makeadr(bank, offset):
    return (bank << 16) | offset

def fileoffset(adr):
    '''Returns the file offset corresponding to the given address. adr can be
       either a file offset (in which case no transformation occurs) or a hirom
       virtual memory offset.'''
    if 0xC00000 <= adr < 0x1000000:
        return adr - 0xC00000
    else:
        return adr

def snesoffset(adr):
    '''Returns the virtual address corresponding to the given address. adr can
       be a virtual address (in which no transformation occurs) or a file
       offset.'''
    if 0 <= adr <= 0x300000:
        return adr + 0xC00000
    else:
        return adr

# TODO: this should be a parameter
goodbanks = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xEE, 0xEF }

def testwindow(container, start, flags=0):

    is_code = 0
    not_code = 0

    src = iterfrom(container, start)
    address = start + 0xC00000
    status = Status((address & 0xFF0000) >> 16, address & 0xFFFF, flags, flags)

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
    if len(sys.argv) < 4:
        print('''Usage:
    disasm.py <romfile> <dis|testwindow|recursive> <hexoffset> [flagstate]''')
        exit(1)

    filename = sys.argv[1]
    mode = sys.argv[2]
    address = int(sys.argv[3], 16)
    flags = 0
    if len(sys.argv) > 4:
        flags = int(sys.argv[4])

    rom = loadfile(filename)

    if mode == 'dis':
        src = iterfrom(rom, fileoffset(address))
        disassemble(src, snesoffset(address), flags)
    elif mode == 'testwindow':
        testwindow(rom, address, flags)
    elif mode == 'recursive':
        m,x = flags,flags
        address = snesoffset(address)
        status = Status(bank(address), offset(address), m, x)

        # Perform recursive disassembly
        entities,status = recursive_disassemble(rom, address, status)

        # Get instructions as a list, sorted by address
        instructions = [(k,v) for k,v in entities.items() if isinstance(v, Instruction)]
        instructions = [inst for (adr,inst) in sorted(instructions, key=lambda i: i[0])]

        print('Main segment:')
        for inst in instructions:
            print(disassembly(inst))

        # Sort subroutines by address
        subroutines = [v for k,v in entities.items() if isinstance(v, Subroutine)]
        subroutines = sorted(subroutines, key = lambda s: s.address)

        print('Identified {} subroutines:'.format(len(subroutines)))
        for i,s in enumerate(subroutines):
            print('Subroutine {} (${:06X}):'.format(i, s.address))
            for inst in s.instructions:
                print(disassembly(inst))
            print('')

        

    #src = iterfrom(rom, address)
    #disassemble(src, address + 0xC00000)


