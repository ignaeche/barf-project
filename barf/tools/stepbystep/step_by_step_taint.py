#!/usr/bin/env python

import logging
import os
import struct
import sys

from collections import defaultdict

from barf import BARF

from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.x86base import X86ArchitectureInformation
from barf.core.dbg.debugger import ProcessControl, ProcessExit, ProcessEnd
from barf.core.dbg.testcase import prepare_inputs
from barf.core.reil import ReilMnemonic
from barf.core.reil import ReilRegisterOperand

logger = logging.getLogger(__name__)

def get_tainted_operands(instr, emulator):
    tainted_oprnds = []

    if instr.mnemonic == ReilMnemonic.LDM:
        addr = emulator.read_operand(instr.operands[0])
        size = instr.operands[2].size

        if emulator.get_memory_taint(addr, size):
            tainted_oprnds.append(addr)
    else:
        reg_oprnds = [oprnd for oprnd in instr.operands
                        if isinstance(oprnd, ReilRegisterOperand)]
        tainted_oprnds = [oprnd for oprnd in reg_oprnds
                            if emulator.get_operand_taint(oprnd)]

    return tainted_oprnds

def process_tainted_branch_data(c_analyzer, branches_taint_data):
    print("Total branches : %d" % len(branches_taint_data))

    for idx, branch_taint_data in enumerate(branches_taint_data):
        logger.info("Branch analysis #%d" % idx)

        c_analyzer.reset(full=True)

        branch_addr = branch_taint_data['branch_address']
        instrs_list = branch_taint_data['tainted_instructions']
        branch_cond = branch_taint_data['branch_condition_register']
        branch_val = branch_taint_data['branch_condition_value']
        initial_taints = branch_taint_data['initial_taints']
        addrs_to_vars = branch_taint_data['addrs_to_vars']

        # Add initial tainted addresses to the code analyzer.
        mem_exprs = {}

        for tainted_addr in initial_taints:
            for reg, access_size in addrs_to_vars.get(tainted_addr, []):
                addr_expr = c_analyzer.get_operand_var(reg)
                mem_expr = c_analyzer.get_memory_expr(
                                addr_expr, access_size / 8, mode="pre")

                mem_exprs[tainted_addr] = mem_expr

        # Add instructions to the code analyzer.
        for instr in instrs_list[:-1]:
            if instr.mnemonic == ReilMnemonic.JCC and \
                isinstance(instr.operands[0], ReilRegisterOperand):
                op1_var = c_analyzer.get_operand_var(instr.operands[0])

                c_analyzer.add_constraint(op1_var == 0x1)

            c_analyzer.add_instruction(instr)

        # Get a SMT variable for the branch condition.
        branch_cond_var = c_analyzer.get_operand_expr(branch_cond, mode="post")

        # Set wanted branch condition.
        c_analyzer.set_postcondition(branch_cond_var != branch_val)

        # Print results.
        ruler = "# {0} #".format("=" * 76)
        title = "{ruler}\n#{{title}}\n{ruler}".format(ruler=ruler)
        footer = "{0}\n{0}".format("~" * 80)

        print(title.format(title="Tainted Instructions"))
        for instr in instrs_list:
            print instr

        print(title.format(title="Branch Information"))
        print("Branch number : %d" % idx)
        print("Branch address : 0x%08x" % branch_addr)
        print("Branch taken? : %s" % (branch_val == 0x1))

        msg = "mem @ 0x{:08x} : {:02x} ({:s})"
        print(title.format(title="Memory State"))
        for tainted_addr, mem_expr in sorted(mem_exprs.items()):
            value = c_analyzer.get_expr_value(mem_expr)

            print(msg.format(tainted_addr, value, chr(value)))

        print(footer)

def intercept_read_function(pcontrol, process, barf, addr, size):
    print("[+] Intercepting 'read' function...")

    print("[+] Extracting 'read'parameters...")

    esp = process.getreg("rsp") & 2**32-1

    # Extract read function arguments from stack.
    count = struct.unpack("<I", process.readBytes(esp + 0x8, 4))[0]
    buf = struct.unpack("<I", process.readBytes(esp + 0x4, 4))[0]
    fd = struct.unpack("<I", process.readBytes(esp + 0x0, 4))[0]

    print("\tfd: %d" % fd)
    print("\tbuf: 0x%08x" % buf)
    print("\tcount: 0x%x" % count)

    print("[+] Executing 'read' function...")

    next_addr = addr + size

    pcontrol.breakpoint(next_addr)
    pcontrol.cont()

    # Instruction after read function call.
    addr = process.getInstrPointer()
    instr = process.readBytes(addr, 20)

    asm_instr = barf.disassembler.disassemble(instr, addr)
    size = asm_instr.size

    print("[+] Extracting 'read' return value...")

    bytes_read = process.getreg("rax") & 2**32-1

    print("\t# bytes read: %d" % bytes_read)

    return buf, bytes_read

def main(args):
    try:
        filename = os.path.abspath(args[1])

        ea_start = int(args.setdefault(2, "0x0"), 16)
        ea_end = int(args.setdefault(3, "0x0"), 16)

        barf = BARF(filename)
    except Exception as err:
        print(err)
        print("[-] Error opening file : %s" % filename)

        sys.exit(1)

    if barf.testcase is None:
        print("No testcase specified. Execution impossible")

        sys.exit(-1)

    binary = barf.binary
    args = prepare_inputs(barf.testcase["args"] + barf.testcase["files"])
    pcontrol = ProcessControl()

    print("[+] Executing x86 to REIL...")

    process = pcontrol.start_process(binary, args, ea_start, ea_end)

    ir_emulator = barf.ir_emulator
    c_analyzer = barf.code_analyzer
    c_analyzer.set_arch_info(barf.arch_info)

    arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    # NOTE: Temporary hack to interface correctly with ptrace.debbuger.
    arch_info64 = X86ArchitectureInformation(ARCH_X86_MODE_64)

    registers = arch_info.registers_gp_base
    mapper = arch_info64.registers_access_mapper()

    # Hardcoded 'read' function addresses.
    # read_addr = 0x080483b0 << 0x8   # taint
    read_addr = 0x080483f0 << 0x8   # serial

    branches_taint_data = []
    tainted_instrs = []
    initial_taints = []
    addrs_to_vars = defaultdict(lambda: [])

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

        # Set REIL emulator context.
        ir_emulator._regs = dict(pcontrol.get_context(registers, mapper))

        # Process REIL instructions.
        for reil_instr in reil_instrs:
            # print("{0:14}{1}".format("", reil_instr))

            # If not supported, skip...
            if reil_instr.mnemonic == ReilMnemonic.UNKN:
                continue

            ir_emulator.execute_lite([reil_instr])

            # Intercept 'read' function call.
            if reil_instr.mnemonic == ReilMnemonic.JCC:
                target = ir_emulator.read_operand(reil_instr.operands[2])

                if target == read_addr:
                    # Extract 'read' parameters.
                    buf, bytes_read = intercept_read_function(
                                        pcontrol, process, barf, addr, size)

                    # Taint memory address.
                    ir_emulator.set_memory_taint(buf, bytes_read * 8, True)

                    # Keep record of inital taints.
                    for i in xrange(0, bytes_read):
                        initial_taints.append(buf + i)

                    break

            # Add instructions with tainted operands to a list.
            if len(get_tainted_operands(reil_instr, ir_emulator)) > 0:
                tainted_instrs.append(reil_instr)

            # Pair registers names with tainted memory addresses.
            if reil_instr.mnemonic == ReilMnemonic.LDM and \
                isinstance(reil_instr.operands[0], ReilRegisterOperand):

                addr = ir_emulator.read_operand(reil_instr.operands[0])
                size = reil_instr.operands[2].size

                if ir_emulator.get_memory_taint(addr, size):
                    addrs_to_vars[addr].append((reil_instr.operands[0], size))

            # If there is a conditional jump depending on tainted data
            # generate condition.
            if reil_instr.mnemonic == ReilMnemonic.JCC and \
                isinstance(reil_instr.operands[0], ReilRegisterOperand):

                cond = reil_instr.operands[0]

                if ir_emulator.get_operand_taint(cond):
                    print("[+] Analyzing JCC: Tainted")

                    cond_value = ir_emulator.read_operand(cond)

                    branches_taint_data.append({
                        'branch_address' : addr,
                        'tainted_instructions' : list(tainted_instrs),
                        'branch_condition_register' : cond,
                        'branch_condition_value' : cond_value,
                        'initial_taints' : list(initial_taints),
                        'addrs_to_vars' : dict(addrs_to_vars),
                    })
                else:
                    print("[+] Analyzing JCC: Not Tainted")

        process.singleStep()

        event = pcontrol.wait_event()

        if isinstance(event, ProcessExit):
            print("[+] Process exit.")
            break

        if isinstance(event, ProcessEnd):
            print("[+] Process end.")
            break

    process_tainted_branch_data(c_analyzer, branches_taint_data)


if __name__ == "__main__":
    # NOTE: For now, it works only for programs compiled in 32 bits.
    main(dict(enumerate(sys.argv)))
