#!/usr/bin/env python3

import sys
import ctypes

if sys.platform == 'win32':
    LPVOID  = ctypes.c_void_p
    HANDLE  = LPVOID
    SIZE_T  = ctypes.c_size_t
    DWORD   = ctypes.c_uint32
    LPDWORD = ctypes.POINTER(DWORD)
    PDWORD  = LPDWORD

    def error_if_zero(result, func, args):
        if not result:
            raise ctypes.WinError()
        return result

    PAGE_NOACCESS          = 0x01
    PAGE_READONLY          = 0x02
    PAGE_READWRITE         = 0x04
    PAGE_WRITECOPY         = 0x08
    PAGE_EXECUTE           = 0x10
    PAGE_EXECUTE_READ      = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_GUARD             = 0x100
    PAGE_NOCACHE           = 0x200
    PAGE_WRITECOMBINE      = 0x400

    _VirtualProtect = ctypes.windll.kernel32.VirtualProtect
    _VirtualProtect.argtypes = [LPVOID, SIZE_T, DWORD, PDWORD]
    _VirtualProtect.restype  = bool
    _VirtualProtect.errcheck = error_if_zero
    flOldProtect = DWORD(0)
    def VirtualProtect(lpAddress, dwSize, flNewProtect):
        _VirtualProtect(lpAddress, dwSize, flNewProtect, ctypes.byref(flOldProtect))
        return flOldProtect.value

    def make_memory_executable(buffer):
        VirtualProtect(buffer, ctypes.sizeof(buffer), PAGE_EXECUTE_READWRITE)
else:
    libc = ctypes.CDLL('libc.{}'.format('dylib' if sys.platform == 'darwin' else 'so.6'))

    PAGESIZE = libc.getpagesize()
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4

    mprotect = libc.mprotect
    mprotect.restype = ctypes.c_int
    mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]

    def make_memory_executable(buffer):
        orig = ctypes.addressof(buffer)
        addr = orig & (~(PAGESIZE-1)) # assumes the page size is a pow of 2
        size = ((orig+len(buffer)+PAGESIZE-1) & (~(PAGESIZE-1))) - addr
        ret = mprotect(addr, size, PROT_READ|PROT_WRITE|PROT_EXEC)
        if ret == -1:
            raise Exception('An error occured during mprotect')
def create_executable_buffer(init, size=None):
    if isinstance(init, bytes) and size is None:
        size = len(init)
    buffer = ctypes.create_string_buffer(init, size)
    make_memory_executable(buffer)
    return buffer

def i8_to_bytes(n):
    return bytes([n&0xFF])
def i16_to_bytes(n):
    return bytes([n&0xFF, (n>>8)&0xFF])
def i32_to_bytes(n):
    return bytes([n&0xFF, (n>>8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF])
def i64_to_bytes(n):
    return bytes([
         n     &0xFF, (n>> 8)&0xFF, (n>>16)&0xFF, (n>>24)&0xFF,
        (n>>32)&0xFF, (n>>40)&0xFF, (n>>48)&0xFF, (n>>56)&0xFF
    ])

class Assembler():

    def __init__(self):
        self.chunks = []
        self.labels = []
        self.label_refs = []
        self.pos = 0
        self.poses = []

    def emit(self, raw):
        assert isinstance(raw, bytes)
        self.chunks.append(raw)
        self.poses.append(self.pos)
        self.pos += len(raw)

    def emit_thunk(self, label, nbytes, thunk):
        self.chunks.append(thunk)
        self.poses.append(self.pos)
        self.pos += nbytes
        self.label_refs[label].append(len(self.chunks)-1)
        if self.labels[label] is not None:
            self.resolve(label)

    def resolve(self, label):
        pos = self.labels[label]
        assert pos is not None
        for r in self.label_refs[label]:
            self.chunks[r] = self.chunks[r](self.poses[r], pos)
        self.label_refs[label] = []

    def label(self):
        self.labels.append(None)
        self.label_refs.append([])
        return len(self.labels)-1

    def put_label(self, label):
        assert self.labels[label] is None
        self.labels[label] = self.pos
        self.resolve(label)

    def assemble(self):
        return b''.join(self.chunks)

def parse(string):
    if len(string) == 0: return ([], '')
    c, rest = string[0], string[1:]
    if c == '[':
        subexpr, rem = parse(rest)
        assert rem[0] == ']'
        expr, rem = parse(rem[1:])
        return ([subexpr]+expr, rem)
    elif c == ']':
        return ([], string)
    elif c in '+-><.,':
        expr, rem = parse(rest)
        return ([c]+expr, rem)
    else:
        return parse(rest)

def inc_while(pred, lis, pos):
    while pos < len(lis) and pred(lis[pos]):
        pos += 1
    return pos

def optimize(ast):
    pos = 0
    while pos < len(ast):
        cur = ast[pos]
        if cur in ('+', '-'):
            newpos = inc_while(lambda i: i in ('+', '-'), ast, pos)
            seq = ast[pos:newpos]
            delta = seq.count('+')-seq.count('-')
            if 0 != delta:
                yield ('+', delta)
        elif cur in ('>', '<'):
            newpos = inc_while(lambda i: i in ('>', '<'), ast, pos)
            seq = ast[pos:newpos]
            delta = seq.count('>')-seq.count('<')
            if 0 != delta:
                yield ('>', delta)
        elif isinstance(cur, list):
            yield list(optimize(cur))
            newpos = pos+1
        else:
            yield cur
            newpos = pos+1
        pos = newpos

def invoke(asm, func):
    addr = ctypes.addressof(func)
    asm.emit(b'\x48\xb8') # mov rax, ...
    asm.emit(i64_to_bytes(addr))
    asm.emit(b'\xff\x10') # call qword [rax]
if sys.platform == 'win32':
    libc = ctypes.cdll.msvcrt
    def invoke_putchar(asm):
        asm.emit(b'\x0f\xbe\x0b') # movsx ecx, byte [rbx]
        # shadow space required in windows calling convention
        asm.emit(b'\x48\x83\xec\x20') # sub rsp, 32
        invoke(asm, libc.putchar)
        asm.emit(b'\x48\x83\xc4\x20') # add rsp, 32
    def invoke_getchar(asm):
        asm.emit(b'\x0f\xbe\x0b') # movsx ecx, byte [rbx]
        # shadow space required in windows calling convention
        asm.emit(b'\x48\x83\xec\x20') # sub rsp, 32
        invoke(asm, libc.getchar)
        asm.emit(b'\x48\x83\xc4\x20') # add rsp, 32
        asm.emit(b'\x88\x03') # mov byte [rbx], al
else:
    def invoke_putchar(asm):
        asm.emit(b'\x0f\xbe\x3b') # movsx edi, byte [rbx]
        invoke(asm, libc.putchar)
    def invoke_getchar(asm):
        invoke(asm, libc.getchar)
        asm.emit(b'\x88\x03') # mov byte [rbx], al
def compile_chunk(ast):
    asm = Assembler()
    for i in ast:
        if isinstance(i, list):
            begin = asm.label()
            asm.put_label(begin)
            asm.emit(b'\x80\x3b\x00') # cmp byte [rbx], 0
            end = asm.label()
            asm.emit_thunk(end, 6,
                           lambda cur, target: b'\x0f\x84'+i32_to_bytes(target-cur-6))
            asm.emit(compile_chunk(i))
            asm.emit_thunk(begin, 5,
                           lambda cur, target: b'\xe9'+i32_to_bytes(target-cur-5))
            asm.put_label(end)
        elif isinstance(i, tuple) and i[0] == '+':
            asm.emit(b'\x80\x03') # add byte [rbx], ...
            asm.emit(i8_to_bytes(i[1]))
        elif isinstance(i, tuple) and i[0] == '>':
            asm.emit(b'\x48\x81\xc3') # add rbx, ...
            asm.emit(i32_to_bytes(i[1]))
        elif i == '.':
            invoke_putchar(asm)
        elif i == ',':
            invoke_getchar(asm)
        else:
            raise Exception('unhandled node: {}'.format(repr(i)))
    return asm.assemble()

def compile_bf(ast, bufaddr):
    asm = Assembler()
    asm.emit(b'\x53')            # push rbx
    asm.emit(b'\x48\xbb')        # mov rbx, ...
    asm.emit(i64_to_bytes(bufaddr))
    asm.emit(compile_chunk(ast))
    asm.emit(b'\x5b')            # pop rbx
    asm.emit(b'\xc3')            # ret
    return asm.assemble()

def main(argv):
    if len(argv) == 0:
        bf = sys.stdin.buffer.read()
    else:
        bf = open(argv[0], 'rb').read()
    bf = bf.decode('ascii')
    ast, rem = parse(bf)
    assert len(rem) == 0
    mem = ctypes.create_string_buffer(30000)
    code = compile_bf(optimize(ast), ctypes.addressof(mem))
    with open('obj', 'wb') as fp:
        fp.write(code)
    buf = create_executable_buffer(code)
    ctypes.CFUNCTYPE(None)(ctypes.addressof(buf))()
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
