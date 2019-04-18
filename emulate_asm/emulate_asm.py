import sys
capstone_loaded = False
keystone_loaded = False
unicorn_loaded = False
try:
    from unicorn import *
    from unicorn.x86_const import *
    unicorn_loaded = True
except:
    print "[!] cannot import unicorn engine, install with 'pip' (linux) or https://www.unicorn-engine.org/ (windows)"
    pass
try:
    from capstone import *
    capstone_loaded = True
except:
    print "[!] cannot import capstone engine, install with 'pip install capstone'"
    pass
try:
    from keystone import *
    keystone_loaded = True
except:
    print "[!] cannot import keystone engine, install with pip (linux) or https://www.keystone-engine.org/ (windows)"
    pass

def args_parser():
    import argparse
    parser = argparse.ArgumentParser(description="--- ASMDeCode ---")
    parser.add_argument("-a","--assemble", action="store_true", help="Assemble")
    parser.add_argument("-d","--disassemble", action="store_true", help="Disassemble")
    parser.add_argument("-e","--emulate", action="store_true", help="Emulate and dump final context and provide memory areas")
    parser.add_argument("-x64","--x8664", action="store_true", help="Use intel x86_64 syntax")
    parser.add_argument("-f","--file", metavar="<file>", help="file (hex encoded opcodes / asm code)")
    parser.add_argument("-c","--cmdl", metavar="<cmdl>", help="data (hex encoded opcodes / asm code with ; between lines)")
    parser.add_argument("-x","--outCArray", action="store_true", help="print C array opcodes instead of hexdump")
    parser.add_argument("--ax", metavar="<ax>", help="AX register (EAX/RAX)", default=None)
    parser.add_argument("--bx", metavar="<bx>", help="BX register (EBX/RBX)", default=None)
    parser.add_argument("--cx", metavar="<cx>", help="CX register (ECX/RCX)", default=None)
    parser.add_argument("--dx", metavar="<dx>", help="DX register (EDX/RDX)", default=None)
    parser.add_argument("--di", metavar="<si>", help="SI register (ESI/RSI)", default=None)
    parser.add_argument("--si", metavar="<di>", help="DI register (EDI/RDI)", default=None)
    parser.add_argument("--bp", metavar="<bp>", help="BP register (EDP/RBP)", default=None)
    parser.add_argument("--sp", metavar="<sp>", help="SP register (ESP/RSP)", default=None)
    parser.add_argument("--r8", metavar="<r8>", help="R8 register", default=None)
    parser.add_argument("--r9", metavar="<r9>", help="R9 register", default=None)
    parser.add_argument("--r10", metavar="<r10>", help="R10 register", default=None)
    parser.add_argument("--r11", metavar="<r11>", help="R11 register", default=None)
    parser.add_argument("--r12", metavar="<r12>", help="R12 register", default=None)
    parser.add_argument("--r13", metavar="<r13>", help="R13 register", default=None)
    parser.add_argument("--r14", metavar="<r14>", help="R14 register", default=None)
    parser.add_argument("--r15", metavar="<r15>", help="R15 register", default=None)
    parser.add_argument("--mem1A", metavar="<mem1A>", help="First memory address", default=None)
    parser.add_argument("--mem1V", metavar="<mem1V>", help="First memory data (hex encoded)", default=None)
    parser.add_argument("--mem2A", metavar="<mem2A>", help="Second memory address", default=None)
    parser.add_argument("--mem2V", metavar="<mem2V>", help="Second memory data (hex encoded)", default=None)
    parser.add_argument("--mem3A", metavar="<mem3A>", help="Third memory address", default=None)
    parser.add_argument("--mem3V", metavar="<mem3V>", help="Third memory data (hex encoded)", default=None)
    parser.add_argument("--mem4A", metavar="<mem4A>", help="Fourth memory address", default=None)
    parser.add_argument("--mem4V", metavar="<mem4V>", help="Fourth memory data (hex encoded)", default=None)
    return parser

def assemble(data, x64="False", cArray="False"):
    m = KS_ARCH_X86
    ms = KS_MODE_32
    if x64 is True:
        ms = KS_MODE_64
    ks = Ks(m, ms)
    encoding, count = ks.asm(data)
    if cArray is False:
        print ''.join(chr(x) for x in encoding).encode("hex")
    else:
        print '{ 0x'+', 0x'.join(str(j) for j in encoding)+" }"
    return ''.join(chr(x) for x in encoding).encode("hex")

# *=2 just in case
def getNeededSize(x):
    return ((len(x) & ~0xFFF) + 0x1000)*2

def emulate(data, x64=False, ax=None, bx=None, cx=None, dx=None, si=None, di=None, bp=None, sp=None, r8=None, r9=None, r10=None, r11=None, r12=None, r13=None, r14=None, r15=None, mem1A=None, mem1V=None, mem2A=None, mem2V=None, mem3A=None, mem3V=None, mem4A=None, mem4V=None):
    data = data.decode("hex")
    load_addr = 0x10000
    m = UC_ARCH_X86
    ms = UC_MODE_32
    if x64 is True:
        ms = UC_MODE_64
    mu = Uc(m, ms)
    # map code
    print "\t[-] Mapping code at 0x%x" % (load_addr)
    mu.mem_map(load_addr, getNeededSize(data))
    mu.mem_write(load_addr, data)
    # map memory areas
    if mem4A != None and mem4V != None:
        if mem4A.startswith("0x"):
            mem4A =int(mem4A,16)
        else:
            mem4A =int(mem4A)
        mem4V = mem4V.decode("hex")
        print "\t[-] Mapping data at 0x%x" % (mem4A)
        mu.mem_map(mem4A, getNeededSize(mem4V))
        mu.mem_write(mem4A, mem4V)
    if mem3A != None and mem3V != None:
        if mem3A.startswith("0x"):
            mem3A =int(mem3A,16)
        else:
            mem3A =int(mem3A)
        mem3V = mem3V.decode("hex")
        print "\t[-] Mapping data at 0x%x" % (mem3A)
        mu.mem_map(mem3A, getNeededSize(mem3V))
        mu.mem_write(mem3A, mem3V)
    if mem2A != None and mem2V != None:
        if mem2A.startswith("0x"):
            mem2A =int(mem2A,16)
        else:
            mem2A =int(mem2A)
        mem2V = mem2V.decode("hex")
        print "\t[-] Mapping data at 0x%x" % (mem2A)
        mu.mem_map(mem2A, getNeededSize(mem2V))
        mu.mem_write(mem2A, mem2V)
    if mem1A != None and mem1V != None:
        if mem1A.startswith("0x"):
            mem1A =int(mem1A,16)
        else:
            mem1A =int(mem1A)
        mem1V = mem1V.decode("hex")
        print "\t[-] Mapping data at 0x%x" % (mem1A)
        mu.mem_map(mem1A, getNeededSize(mem1V))
        mu.mem_write(mem1A, mem1V)
    # set registers
    if x64 is True:
        if ax is not None:
            mu.reg_write(UC_X86_REG_RAX, ax)
        if bx is not None:
            mu.reg_write(UC_X86_REG_RBX, bx)
        if cx is not None:
            mu.reg_write(UC_X86_REG_RCX, cx)
        if dx is not None:
            mu.reg_write(UC_X86_REG_RDX, dx)
        if si is not None:
            mu.reg_write(UC_X86_REG_RSI, si)
        if di is not None:
            mu.reg_write(UC_X86_REG_RDI, di)
        if bp is not None:
            mu.reg_write(UC_X86_REG_RBP, bp)
        if sp is not None:
            mu.reg_write(UC_X86_REG_RSP, sp)
        if r8 is not None:
            mu.reg_write(UC_X86_REG_R8, r8)
        if r9 is not None:
            mu.reg_write(UC_X86_REG_R9, r9)
        if r10 is not None:
            mu.reg_write(UC_X86_REG_R10, r10)
        if r11 is not None:
            mu.reg_write(UC_X86_REG_R11, r11)
        if r12 is not None:
            mu.reg_write(UC_X86_REG_R12, r12)
        if r13 is not None:
            mu.reg_write(UC_X86_REG_R13, r13)
        if r14 is not None:
            mu.reg_write(UC_X86_REG_R14, r14)
        if r15 is not None:
            mu.reg_write(UC_X86_REG_R15, r15)
    else:
        if ax is not None:
            mu.reg_write(UC_X86_REG_EAX, ax)
        if bx is not None:
            mu.reg_write(UC_X86_REG_EBX, bx)
        if cx is not None:
            mu.reg_write(UC_X86_REG_ECX, cx)
        if dx is not None:
            mu.reg_write(UC_X86_REG_EDX, dx)
        if si is not None:
            mu.reg_write(UC_X86_REG_ESI, si)
        if di is not None:
            mu.reg_write(UC_X86_REG_EDI, di)
        if bp is not None:
            mu.reg_write(UC_X86_REG_EBP, bp)
        if sp is not None:
            mu.reg_write(UC_X86_REG_ESP, sp)
    # emulation
    print "\t[-] Emulation"
    mu.emu_start(load_addr, load_addr + len(data))
    print "\t[-] Emulation finished"
    print "\t[-] Context:"
    if x64 is True:
        print "\t\tRAX: %x ; RBX: %x ; RCX: %x ; RDX: %x" % (mu.reg_read(UC_X86_REG_RAX), mu.reg_read(UC_X86_REG_RBX), mu.reg_read(UC_X86_REG_RCX), mu.reg_read(UC_X86_REG_RDX))
        print "\t\tRSI: %x ; RDI: %x ; RBP: %x ; RSP: %x" % (mu.reg_read(UC_X86_REG_RSI), mu.reg_read(UC_X86_REG_RDI), mu.reg_read(UC_X86_REG_RBP), mu.reg_read(UC_X86_REG_RSP))
        print "\t\tR8:  %x ; R9:  %x ; R10: %x ; R11: %x" % (mu.reg_read(UC_X86_REG_R8), mu.reg_read(UC_X86_REG_R9), mu.reg_read(UC_X86_REG_R10), mu.reg_read(UC_X86_REG_R11))
        print "\t\tR12: %x : R13: %x ; R14: %x : R15: %x" % (mu.reg_read(UC_X86_REG_R12), mu.reg_read(UC_X86_REG_R13), mu.reg_read(UC_X86_REG_R14), mu.reg_read(UC_X86_REG_R15))
    else:
        print "\t\tEAX: %x ; EBX: %x ; ECX: %x ; EDX: %x" % (mu.reg_read(UC_X86_REG_EAX), mu.reg_read(UC_X86_REG_EBX), mu.reg_read(UC_X86_REG_ECX), mu.reg_read(UC_X86_REG_EDX))
        print "\t\tESI: %x ; EDI: %x ; EBP: %x ; ESP: %x" % (mu.reg_read(UC_X86_REG_ESI), mu.reg_read(UC_X86_REG_EDI), mu.reg_read(UC_X86_REG_EBP), mu.reg_read(UC_X86_REG_ESP))
    print "\t[-] Memory areas (if any):"
    if mem1A is not None:
        print "\t\tMEMORY1 AT 0x%x" % (mem1A)
        mem1Vn = mu.mem_read(mem1A, getNeededSize(mem1V))
        mem1V = mem1V + '\x00' * (getNeededSize(mem1V) - len(mem1V))
        if mem1V == str(mem1Vn):
            print "\t\t\tNot modified"
        else:
            print str(mem1Vn).encode("hex").rstrip('0')
    if mem2A is not None:
        print "\t\tMEMORY1 AT 0x%x" % (mem2A)
        mem2Vn = mu.mem_read(mem2A, getNeededSize(mem2V))
        mem2V = mem2V + '\x00' * (getNeededSize(mem2V) - len(mem2V))
        if mem2V == str(mem2Vn):
            print "\t\t\tNot modified"
        else:
            print str(mem2Vn).encode("hex").rstrip('0')
    if mem3A is not None:
        print "\t\tMEMORY1 AT 0x%x" % (mem3A)
        mem3Vn = mu.mem_read(mem3A, getNeededSize(mem3V))
        mem3V = mem3V + '\x00' * (getNeededSize(mem3V) - len(mem3V))
        if mem3V == str(mem3Vn):
            print "\t\t\tNot modified"
        else:
            print str(mem3Vn).encode("hex").rstrip('0')
    if mem4A is not None:
        print "\t\tMEMORY1 AT 0x%x" % (mem4A)
        mem4Vn = mu.mem_read(mem4A, getNeededSize(mem4V))
        mem4V = mem4V + '\x00' * (getNeededSize(mem4V) - len(mem4V))
        if mem4V == str(mem4Vn):
            print "\t\t\tNot modified"
        else:
            print str(mem4Vn).encode("hex").rstrip('0')
    return

def disassemble(data, x64=False):
    data = data.decode("hex")
    m = CS_ARCH_X86
    ms = CS_MODE_32
    if x64 is True:
        ms = CS_MODE_64
    md = Cs(m,ms)
    for i in md.disasm(data,0x1000):
        print "\t0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
    return

if __name__ == '__main__':
    parser = args_parser()
    args = parser.parse_args()
    if not args.file and not args.cmdl:
        print "[!] Need something to work on"
        sys.exit(0)
    if not args.assemble and not args.disassemble:
        print "[!] Need something to do"
        sys.exit(0)
    data = ''
    if args.file:
        data= open(args.file,"rb").read()
    else:
        data = args.cmdl

    x64 = False
    if args.x8664:
        x64 = True
    cArray = False
    if args.outCArray:
        cArray = True

    if args.assemble:
        if keystone_loaded is False:
            print "Keystone engine not found"
        else:
            if args.emulate or args.disassemble:
                cArray == False
            print "[+] Assembly:"
            data = assemble(data, x64=x64, cArray=cArray)

    if args.disassemble:
        if capstone_loaded is False:
            print "Capstone engine not found"
        else:
            print "[+] Disassembly:"
            disassemble(data, x64=x64)
    
    if args.emulate:
        if unicorn_loaded is False:
            print "Unicorn engine not found"
        else:
            print "[+] Emulation:"
            emulate(data, x64=x64, ax=args.ax, bx=args.bx, cx=args.cx, dx=args.dx, si=args.si, di=args.di, bp=args.bp, sp=args.sp, r8=args.r8, r9=args.r9, r10=args.r10, r11=args.r11, r12=args.r12, r13=args.r13, r14=args.r14, r15=args.r15, mem1A=args.mem1A, mem1V=args.mem1V, mem2A=args.mem2A, mem2V=args.mem2V, mem3A=args.mem3A, mem3V=args.mem3V, mem4A=args.mem4A, mem4V=args.mem4V)

