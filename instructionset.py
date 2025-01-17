
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
    0x54 : 'MVN src,dst',
    0x44 : 'MVP src,dst',

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
# Some useful predicates over the instruction set
#------------------------------------------------------------------------------

def isbranch(op):
    '''Returns True iff op is a branching instruction OTHER THAN BRL or BRA.'''
    return op in { 0x90, 0xB0, 0xF0, 0xD0, 0x30, 0x10, 0x50, 0x70 }


def isreturn(op):
    '''Returns True iff op is RTL or RTS.'''
    return op in { 0x60, 0x6B }

def isjmp(op):
    '''Returns True iff op is an absolute jump.'''
    return op in { 0x4C, 0x5C }

def isindirectjmp(op):
    '''Returns True iff op is an indirect (untraceable) jump.'''
    return op in { 0x6C, 0x7C, 0xDC, 0xFC }





