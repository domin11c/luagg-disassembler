#!/usr/bin/env python3

# ======================================================
# Coded by: https://github.com/domin11c
# ======================================================

from sys import argv
import struct

class disassembler:
    input = None
    index = None
    file = None
    outpath = None

    littleEndian = None
    sizeT = None
    sizeNumber = None

    opNames = [
        'MOVE',
        'LOADK',
        'LOADKX',
        'LOADBOOL',
        'LOADNIL',
        'GETUPVAL',
        'GETTABUP',
        'GETTABLE',
        'SETTABUP',
        'SETUPVAL',
        'SETTABLE',
        'NEWTABLE',
        'SELF',
        'ADD',
        'SUB',
        'MUL',
        'DIV',
        'MOD',
        'POW',
        'UNM',
        'NOT',
        'LEN',
        'CONCAT',
        'JMP',
        'EQ',
        'LT',
        'LE',
        'TEST',
        'TESTSET',
        'CALL',
        'TAILCALL',
        'RETURN',
        'FORLOOP',
        'FORPREP',
        'TFORCALL',
        'TFORLOOP',
        'SETLIST',
        'CLOSURE',
        'VARARG',
        'EXTRAARG',
        'IDIV',
        'BNOT',
        'BAND',
        'BOR',
        'BXOR',
        'SHL',
        'SHR'
    ]

    instructionMappings = [
        'iABC',
        'iABx',
        'iABx',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iAsBx',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iAsBx',
        'iAsBx',
        'iABC',
        'iAsBx',
        'iABC',
        'iABx',
        'iABC',
        'iAx',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
        'iABC',
    ]

    def __init__(self, path):
        self.input = open(path, 'rb').read()
        self.index = 0
        self.outpath = path + '.lasm'
        self.readHeader()

    def readHeader(self):
        assert self.readBytes(4) == b'\x1bLua', 'Invalid lua signature'
        assert self.readUInt8() == 0x52, 'Invalid lua version'
        assert self.readUInt8() == 0, 'Invalid lua format'

        self.littleEndian = self.readUInt8() != 0
        self.readUInt8()
        self.sizeT = self.readUInt8()
        self.readUInt8()
        self.sizeNumber = self.readUInt8()
        self.readUInt8()

        assert self.readBytes(6) == b'\x19\x93\r\n\x1a\n', 'Invalid lua tail'

    def readBytes(self, size):
        bytes = self.input[self.index : self.index + size]
        self.index += size
        return bytes
    
    def readUInt8(self):
        return struct.unpack('b', self.readBytes(1))[0]

    def readUInt32(self):
        return struct.unpack('<I' if self.littleEndian else '>I', self.readBytes(4))[0]
    
    def readUInt64(self):
        return struct.unpack('<Q' if self.littleEndian else '>Q', self.readBytes(8))[0]
    
    def readNumber(self):
        if self.sizeNumber == 4:
            return struct.unpack('<f' if self.littleEndian else '>f', self.readBytes(4))[0]
        else:
            return struct.unpack('<d' if self.littleEndian else '>d', self.readBytes(8))[0]
    
    def readSizeT(self):
        return self.readUInt32() if self.sizeT == 4 else self.readUInt64()
    
    def readChunk(self):
        lineDefined = self.readUInt32()
        lastLineDefined = self.readUInt32()
        numParams = self.readUInt8()
        isVararg = self.readUInt8()
        maxStackSize = self.readUInt8()

        instructions = []
        constants = []
        functions = []
        upvalues = []

        for i in range(self.readUInt32()):
            code = self.readUInt32()
            op = code & 0x3f
            type = self.instructionMappings[op]
            opName = self.opNames[op]

            A = (code >> 6) & 0xFF
            B = 0
            C = 0
            Ax = (code >> 6) & 0x3FFFFFF

            match type:
                case 'iABC':
                    B = (code >> 23) & 0x1FF
                    C = (code >> 14) & 0x1FF
                case 'iABx':
                    B = (code >> 14) & 0x3FFFF
                case 'iAsBx':
                    B = ((code >> 14) & 0x3FFFF) - 131071
                case 'iAx':
                    pass

            instructions.append(dict(
                code = code,
                type = type,
                opName = opName,
                A = A,
                B = B,
                C = C,
                Ax = Ax
            ))
        
        for i in range(self.readUInt32()):
            t = self.readUInt8()
            k = None

            match t:
                case 1: k = self.readUInt8()
                case 3: k = self.readNumber()
                case 4: k = self.readBytes(self.readSizeT())[:-1]
            
            constants.append(dict(
                type=t,
                data=k
            ))

        for i in range(self.readUInt32()):
            functions.append(self.readChunk())

        for i in range(self.readUInt32()):
            upvalues.append(dict(
                inStack = self.readUInt8() == 1,
                index = self.readUInt8()
            ))
        
        self.readBytes(self.readSizeT())

        for i in range(self.readUInt32()):
            self.readUInt32()
        
        for i in range(self.readUInt32()):
            self.readBytes(self.readSizeT())
            self.readUInt32()
            self.readUInt32()
        
        for i in range(self.readUInt32()):
            self.readBytes(self.readSizeT())
        
        return dict(
            lineDefined = lineDefined,
            lastLineDefined = lastLineDefined,
            numParams = numParams,
            isVararg = isVararg,
            maxStackSize = maxStackSize,
            instructions = instructions,
            constants = constants,
            functions = functions,
            upvalues = upvalues
        )
    
    def writeChunk(self, name, chunk):
        self.file.write('function ' + name + '\n')
        self.file.write('\t.lineDefined ' + str(chunk['lineDefined']) + '\n')
        self.file.write('\t.lastLineDefined ' + str(chunk['lastLineDefined']) + '\n')
        self.file.write('\t.numParams ' + str(chunk['numParams']) + '\n')
        self.file.write('\t.isVararg ' + str(chunk['isVararg']) + '\n')
        self.file.write('\t.maxStackSize ' + str(chunk['maxStackSize']) + '\n')

        self.file.write('\n\t.constants ' + str(len(chunk['constants'])) + '\n')
        for const in chunk['constants']:
            type = const['type']
            data = const['data']

            self.file.write(str(type) + ' ')
            match type:
                case 0: pass
                case 1: self.file.write(str(data))
                case 3: self.file.write(str(data))
                case 4:
                    for byte in data:
                        self.file.write('\\' + str(byte))
            
            self.file.write('\n')

        self.file.write('\n')
        for inst in chunk['instructions']:
            opName = inst['opName']
            A = inst['A']
            B = inst['B']
            C = inst['C']
            Ax = inst['Ax']
            self.file.write(opName + ' ')

            match inst['type']:
                case 'iABC':
                    self.file.write(str(A) + ' ')
                    self.file.write(str(B) + ' ')
                    self.file.write(str(C) + ' ')
                case 'iABx':
                    self.file.write(str(A) + ' ')
                    self.file.write(str(B) + ' ')
                case 'iAsBx':
                    self.file.write(str(A) + ' ')
                    self.file.write(str(B) + ' ')
                case 'iAx':
                    self.file.write(str(Ax) + ' ')

            self.file.write('\n')

        self.file.write('\n')
        for i in range(len(chunk['functions'])):
            function = chunk['functions'][i]
            self.writeChunk(name + '/' + str(i), function)

    def writeMain(self, chunk):
        open(self.outpath, 'w').close()
        self.file = open(self.outpath, 'a')
        self.writeChunk('main', chunk)

    def disasm(self):
        self.writeMain(self.readChunk())
        
def usage():
    print('Usage: ./disassembler <input>')
    exit(1)

if __name__ == '__main__':
    if len(argv) != 2:
        usage()

    disassembler(argv[1]).disasm()