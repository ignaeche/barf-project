#!/usr/bin/env python

import logging
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

logger = logging.getLogger(__name__)

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

def _extract_value(main_value, offset, size):
    return (main_value >> offset) & 2**size-1

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

    ir_emulator = barf.ir_emulator
    smt_translator = barf.smt_translator
    c_analyzer = barf.code_analyzer

    arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    arch_info64 = X86ArchitectureInformation(ARCH_X86_MODE_64)

    registers = arch_info.registers_gp_base
    mapper = arch_info64.registers_access_mapper()

    process = pcontrol.start_process(binary, args, ea_start, ea_end)

    # read_addr = 0x80483b0 << 0x8    # taint
    read_addr = 0x80483f0 << 0x8    # serial

    tainted_instrs = []
    curr_tainted_instrs = []
    initial_taints = {}
    addrs_to_vars = {}

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
            # If not supported, skip emulation.
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

                for i in xrange(0, bytes_read):
                    initial_taints[buf + i] = True

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
                    if cond.name in ir_emulator.registers:
                        cond_value = ir_emulator.registers[cond.name]
                    elif cond.name in mapper:
                        base_reg, offset = mapper[cond.name]
                        base_reg = 'eflags' if base_reg == 'rflags' else base_reg
                        main_value = reil_context_out[base_reg]
                        cond_value = _extract_value(main_value, offset, cond.size)
                    else:
                        raise Exception("Error!")

                    tainted_instrs.append((addr, list(curr_tainted_instrs), cond.name, cond.size, cond_value))
                else:
                    print "    Not tainted JCC!!!!"
            else:
                # Add instructions with tainted operands to a list.
                reg_operands = [oprnd for oprnd in reil_instr.operands if isinstance(oprnd, ReilRegisterOperand)]
                taints = [ir_emulator.is_tainted(oprnd.name) for oprnd in reg_operands]

                if any(taints):
                    curr_tainted_instrs.append(reil_instr)

            # Pair registers names with tainted memory addresses.
            if reil_instr.mnemonic == ReilMnemonic.LDM and \
                isinstance(reil_instr.operands[0], ReilRegisterOperand):

                reg_name = reil_instr.operands[0].name
                addr = ir_emulator.registers[reg_name]
                size = reil_instr.operands[2].size

                if ir_emulator._mem.is_tainted(addr, size):
                    if addr not in addrs_to_vars:
                        addrs_to_vars[addr]  = [(reg_name, size)]
                    else:
                        addrs_to_vars[addr] += [(reg_name, size)]

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

    print "Total branches : ", len(tainted_instrs)

    # branch_addr, instr_list, cond_name, cond_size, cond_value = tainted_instrs[0]

    for idx, tainted_instrs_info in enumerate(tainted_instrs):

        logger.info("Branch analysis #%d" % idx)

        branches = []

        c_analyzer.reset(full=True)

        branch_addr, instr_list, cond_name, cond_size, cond_value = tainted_instrs_info

        # for instr in instr_list:
        #     print instr

        # Add initial tainted addresses to the code analyzer.
        mem_exprs = {}

        for tainted_addr in initial_taints:
            for reg_name, size in addrs_to_vars.get(tainted_addr, []):
                addr_expr = c_analyzer.get_tmp_register_expr(reg_name, 32)
                mem_expr = c_analyzer.get_memory_expr(addr_expr, size / 8, mode="pre")

                # Extra restriction: generate printable ASCIIs.
                c_analyzer.set_preconditions([mem_expr >= 0x20, mem_expr <= 0x7e])

                mem_exprs[tainted_addr] = mem_expr

        # Add instructions to the code analyzer.
        for instr in instr_list[:-1]:

            if instr.mnemonic == ReilMnemonic.JCC and \
                isinstance(instr.operands[0], ReilRegisterOperand):
                op1_var = c_analyzer._translator._translate_src_oprnd(instr.operands[0])
                imm = c_analyzer.get_immediate_expr(0x1, instr.operands[0].size)

                c_analyzer._solver.add(op1_var == imm)

            c_analyzer.add_instruction(instr)

        # Get a SMT variable for the branch condition.
        if cond_name in arch_info.registers_flags:
            cond = c_analyzer.get_register_expr(cond_name, mode="post")
        else:
            cond = c_analyzer.get_tmp_register_expr(cond_name, cond_size, mode="post")

        # Set branch condition.
        c_analyzer.set_postconditions([cond != cond_value])

        # Print result.
        print("-" * 80)

        print("Branch #%d" % idx)
        print("Branch address : 0x%08x" % branch_addr)
        print("Branch taken? : %s" % (c_analyzer.get_expr_value(cond) == 1))

        for tainted_addr, mem in sorted(mem_exprs.items()):
            mem_value = c_analyzer.get_expr_value(mem)

            print("mem @ 0x%08x : %s (%s)" % (tainted_addr, hex(mem_value), chr(mem_value)))

        print("~" * 80)
        print("~" * 80)
