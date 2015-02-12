#!/usr/bin/env python

import os
import struct
import sys

from barf import BARF

from barf.core.dbg.debugger import ProcessControl, ProcessExit, ProcessSignal, ProcessEnd
from barf.core.dbg.testcase import GetTestcase, prepare_inputs
from barf.core.reil import ReilImmediateOperand
from barf.core.reil import ReilMnemonic
from barf.arch.x86.x86base import X86ArchitectureInformation
from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.core.reil import ReilMnemonic
from barf.core.reil import ReilRegisterOperand

def __compare_contexts(context_init, x86_context, reil_context):
    match = True
    mask = 2**64-1

    for reg in sorted(context_init.keys()):
        if (x86_context[reg] & mask) != (reil_context[reg] & mask):
            match = False
            break

    return match

def __print_contexts(context_init, x86_context, reil_context):
    out = "Contexts don't match!\n\n"

    header_fmt = " {0:^8s} : {1:^16s} | {2:>16s} ?= {3:<16s}\n"
    header = header_fmt.format("Register", "Initial", "x86", "REIL")
    ruler = "-" * len(header) + "\n"

    out += header
    out += ruler

    fmt = " {0:>8s} : {1:016x} | {2:016x} {eq} {3:016x} {marker}\n"

    mask = 2**64-1

    for reg in sorted(context_init.keys()):
        if (x86_context[reg] & mask) != (reil_context[reg] & mask):
            eq, marker = "!=", "<"
        else:
            eq, marker = "==", ""

        out += fmt.format(
            reg,
            context_init[reg] & mask,
            x86_context[reg] & mask,
            reil_context[reg] & mask,
            eq=eq,
            marker=marker
        )

    # Pretty print flags.
    reg = "rflags"
    fmt = "{0:s} ({1:>4s}) : {2:016x} ({3:s})"

    x86_value = x86_context[reg] & mask
    reil_value = reil_context[reg] & mask

    if x86_value != reil_value:
        x86_flags_str = __print_flags(x86_context[reg])
        reil_flags_str = __print_flags(reil_context[reg])

        out += "\n"
        out += fmt.format(reg, "x86", x86_value, x86_flags_str) + "\n"
        out += fmt.format(reg, "reil", reil_value, reil_flags_str)

    return out

def __print_flags(flags_reg):
    # flags
    flags = {
         0 : "cf",  # bit 0
         2 : "pf",  # bit 2
         4 : "af",  # bit 4
         6 : "zf",  # bit 6
         7 : "sf",  # bit 7
        11 : "of",  # bit 11
        10 : "df",  # bit 10
    }

    out = ""

    for bit, flag in flags.items():
        flag_str = flag.upper() if flags_reg & 2**bit else flag.lower()
        out +=  flag_str + " "

    return out[:-1]

def __fix_reil_flag(arch_info, reil_context, x86_context, flag):
    reil_context_out = dict(reil_context)

    flags_reg = 'eflags' if 'eflags' in reil_context_out else 'rflags'

    arch_size = arch_info.architecture_size

    _, bit = arch_info.registers_access_mapper()[flag]

    # Clean flag.
    reil_context_out[flags_reg] &= ~(2**bit) & (2**32-1)

    # Copy flag.
    reil_context_out[flags_reg] |= (x86_context[flags_reg] & 2**bit)

    return reil_context_out

def __fix_reil_flags(self, reil_context, x86_context):
    reil_context_out = dict(reil_context)

    # Remove this when AF and PF are implemented.
    reil_context_out = __fix_reil_flag(reil_context_out, x86_context, "af")
    reil_context_out = __fix_reil_flag(reil_context_out, x86_context, "pf")

    return reil_context_out

if __name__ == "__main__":
    args = dict(enumerate(sys.argv))
    try:
        filename = os.path.abspath(args[1])
        ea_start = int(args.setdefault(2, "0x0"), 16)
        ea_end   = int(args.setdefault(3, "0x0"), 16)
        barf = BARF(filename)

    except Exception as err:
        print err
        print "[-] Error opening file : %s" % filename

        sys.exit(1)

    print("[+] Executing x86 to REIL...")

    if barf.testcase is None:
        print "No testcase specified. Execution impossible"
        sys.exit(-1)

    binary = barf.binary
    args = prepare_inputs(barf.testcase["args"] + barf.testcase["files"])
    pcontrol = ProcessControl()

    barf.ir_translator.reset()

    ir_emulator = barf.ir_emulator
    smt_translator = barf.smt_translator
    c_analyzer = barf.code_analyzer

    arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    arch_info64 = X86ArchitectureInformation(ARCH_X86_MODE_64)

    registers = arch_info.registers_gp_base
    mapper = arch_info64.registers_access_mapper()
    sizes = arch_info.registers_size

    tainted_instrs = []
    curr_tainted_instrs = []

    process = pcontrol.start_process(binary, args, ea_start, ea_end)

    read_addr = 0x80483b0 << 0x8

    while pcontrol:
        # Get some bytes from current IP.
        addr = process.getInstrPointer()
        instr = process.readBytes(addr, 20)

        # Disassemble current native instruction.
        asm_instr = barf.disassembler.disassemble(instr, addr)
        size = asm_instr.size

        print("0x{0:08x} : {1}".format(addr, asm_instr))

        # Translate native instruction to REIL.
        reil_instrs = barf.ir_translator.translate(asm_instr)

        # Emulate current instruction.
        if "unkn" in [reil_instr.mnemonic_str for reil_instr in reil_instrs]:
            print "Skip emulation...."
        else:
            context = pcontrol.get_context(registers, mapper)

            reil_context_out, _ = ir_emulator.execute_lite(reil_instrs, context=context)

        for reil_instr in reil_instrs:
            # print("{0:14}{1}".format("", reil_instr))

            # Catch 'read' function call.
            if reil_instr.mnemonic == ReilMnemonic.JCC and \
                isinstance(reil_instr.operands[2], ReilImmediateOperand) and \
                reil_instr.operands[2].immediate == read_addr:

                # Extract read function arguments from stack.
                print "[+] Intercepting 'read' function..."

                rsp = process.getreg("rsp")
                esp = rsp & 2**32-1

                count = struct.unpack("<I", process.readBytes(esp + 0x8, 4))[0]
                buf = struct.unpack("<I", process.readBytes(esp + 0x4, 4))[0]
                fd = struct.unpack("<I", process.readBytes(esp + 0x0, 4))[0]

                print "\t[+] Extracting parameters..."
                print "\t\tfd: %d" % fd
                print "\t\tbuf: 0x%08x" % buf
                print "\t\tcount: 0x%x" % count

                print "\t[+] Executing function..."

                next_addr = addr + size

                pcontrol.breakpoint(next_addr)
                pcontrol.cont()

                # Instruction after read function call.
                addr = process.getInstrPointer()
                instr = process.readBytes(addr, 20)

                asm_instr = barf.disassembler.disassemble(instr, addr)
                size = asm_instr.size

                bytes_read = process.getreg("rax") & 2**32-1

                print "\t[+] Extracting return value..."
                print "\t\t# bytes read: %d" % bytes_read

                # Taint memory address.
                ir_emulator._mem.taint(buf, bytes_read * 8)

                break

            # If there is a conditional jump depending on tainted data
            # generate condition.
            if reil_instr.mnemonic == ReilMnemonic.JCC and \
                isinstance(reil_instr.operands[0], ReilRegisterOperand):

                print "[+] Analyzing JCC..."

                cond = reil_instr.operands[0]

                if ir_emulator.is_tainted(cond.name):
                    print "    Tainted JCC!!!!"

                    curr_tainted_instrs.append(reil_instr)

                    # Output restrictions on condition.
                    tainted_instrs.append((curr_tainted_instrs, cond.name, ir_emulator.registers[cond.name]))
                    curr_tainted_instrs = []
                else:
                    print "    Not tainted JCC!!!!"

            reg_operands = [oprnd for oprnd in reil_instr.operands if isinstance(oprnd, ReilRegisterOperand)]
            taints = [ir_emulator.is_tainted(oprnd.name) for oprnd in reg_operands]

            if any(taints):
                curr_tainted_instrs.append(reil_instr)

        process.singleStep()

        # Check native context vs emulated context.
        # x86_context_out = pcontrol.get_context(registers, mapper)

        # ctx_eq = __compare_contexts(context, x86_context_out, reil_context_out)

        # if not ctx_eq:
        #     __print_contexts(context, x86_context_out, reil_context_out)

        event = pcontrol.wait_event()

        if isinstance(event, ProcessExit):
            print "process exit"
            break

        if isinstance(event, ProcessEnd):
            print "process end"
            break

    print("# " + "=" * 76 + " #")
    print("# Tainted Instructions (REIL):")
    print("# " + "=" * 76 + " #")

    instr_list, cond_name, cond_value = tainted_instrs[0]

    for instr in instr_list:
        print instr

    # Quick hack...
    buf = c_analyzer._solver.mkBitVec(8, "t9605_1")
    cond = c_analyzer._solver.mkBitVec(1, cond_name + "_1")

    c_analyzer.set_preconditions([cond == cond_value])

    for instr in instr_list:
        c_analyzer.add_instruction(instr)

    print("-" * 80)

    print "Path sat:", c_analyzer.check()
    print "buf: ", hex(c_analyzer.get_expr_value(buf))
    print "cond (taken): ", hex(c_analyzer.get_expr_value(cond))

    c_analyzer.reset(full=True)

    buf = c_analyzer._solver.mkBitVec(8, "t9605_1")
    cond = c_analyzer._solver.mkBitVec(1, cond_name + "_1")

    c_analyzer.set_preconditions([cond != cond_value])

    for instr in instr_list:
        c_analyzer.add_instruction(instr)

    print("-" * 80)

    print "Path sat:", c_analyzer.check()
    print "buf: ", hex(c_analyzer.get_expr_value(buf))
    print "cond (not taken): ", hex(c_analyzer.get_expr_value(cond))
