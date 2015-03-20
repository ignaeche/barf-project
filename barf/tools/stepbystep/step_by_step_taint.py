#!/usr/bin/env python

import logging
import os
import platform
import sys
import time

from collections import defaultdict

from barf import BARF

from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.x86base import X86ArchitectureInformation
from barf.core.dbg.debugger import ProcessControl, ProcessExit, ProcessEnd
from barf.core.dbg.testcase import prepare_inputs
from barf.core.dbg.input import File
from barf.core.reil import ReilEmptyOperand
from barf.core.reil import ReilImmediateOperand
from barf.core.reil import ReilMnemonic
from barf.core.reil import ReilRegisterOperand

from hooks import taint_read
from exploration import new_to_explore, next_to_explore, add_to_explore, was_explored

logger = logging.getLogger(__name__)

def get_tainted_operands(instr, emulator):
    """Returns an instruction's tainted operands.
    """
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

def analyze_tainted_branch_data(c_analyzer, branches_taint_data, iteration):
    """For each input branch (which depends on tainted input), it
    prints the values needed to avoid taking that branch.

    """
    print("Total branches : %d" % len(branches_taint_data))

    new_inputs = []

    for idx, branch_taint_data in enumerate(branches_taint_data):
        logger.info("Branch analysis #{}".format(idx))

        c_analyzer.reset(full=True)

        # TODO: Simplify tainted instructions, i.e, remove superfluous
        # instructions.
        # TODO: 'Concretize' not tainted instructions' operands.

        branch_addr = branch_taint_data['branch_address']
        instrs_list = branch_taint_data['tainted_instructions']
        branch_cond = branch_taint_data['branch_condition_register']
        branch_val = branch_taint_data['branch_condition_value']
        initial_taints = branch_taint_data['initial_taints']
        addrs_to_vars = branch_taint_data['addrs_to_vars']
        open_files = branch_taint_data['open_files']
        addrs_to_file = branch_taint_data['addrs_to_file']

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
        title = "{ruler}\n# {{title}}\n{ruler}".format(ruler=ruler)
        footer = "{0}\n{0}".format("~" * 80)

        print(title.format(title="Tainted Instructions"))
        for instr in instrs_list:
            print instr

        if c_analyzer.check() != 'sat':
            print("UnSat Constraints!!!")
            print(footer)
            continue

        print(title.format(title="Branch Information"))
        print("Branch number : %d" % idx)
        print("Branch address : 0x%08x" % branch_addr)
        print("Branch taken? : %s" % (branch_val == 0x1))

        msg = "mem @ 0x{:08x} : {:02x} ({:s})"
        print(title.format(title="Memory State"))
        for tainted_addr, mem_expr in sorted(mem_exprs.items()):
            value = c_analyzer.get_expr_value(mem_expr)

            print(msg.format(tainted_addr, value, chr(value)))

        print(title.format(title="New Input Files"))
        # Generate new input file.
        for fd in open_files:
            filename = open_files[fd]['filename']

            print "File name: ", filename

            with open(filename, "rb") as f:
                byte = f.read(1)
                file_content = bytearray()

                while byte:
                    file_content.append(byte)
                    # Do stuff with byte.
                    byte = f.read(1)

            for tainted_addr, mem_expr in sorted(mem_exprs.items()):
                value = c_analyzer.get_expr_value(mem_expr)

                for fd2, pos_list in addrs_to_file[tainted_addr].items():
                    if fd2 == fd:
                        for p in pos_list:
                            file_content[p] = value

            print "File content: ", file_content

            name, extension = filename.split(".")
            name = name.split("_", 1)[0]

            new_filename = name + "_%03d_%03d" % (iteration, idx) + "." + extension

            with open(new_filename, "wb") as f:
                f.write(file_content)

            #new_inputs.append(new_filename)
            new_inputs.append((filename, file_content))

        print(footer)

    return new_inputs

def concretize_instruction(instruction, emulator):
    if instruction.mnemonic not in [ReilMnemonic.LDM]:

        curr_oprnd0 = instruction.operands[0]
        curr_oprnd1 = instruction.operands[1]

        if isinstance(curr_oprnd0, ReilRegisterOperand) and \
            not isinstance(curr_oprnd1, ReilEmptyOperand) and \
            emulator.get_operand_taint(curr_oprnd0) == False:

            # print "curr_oprnd0", curr_oprnd0, emulator.get_operand_taint(curr_oprnd0)

            value = emulator.read_operand(curr_oprnd0)
            new_oprnd0 = ReilImmediateOperand(value, curr_oprnd0.size)

            instruction.operands[0] = new_oprnd0

        elif isinstance(curr_oprnd1, ReilRegisterOperand) and \
            not isinstance(curr_oprnd1, ReilEmptyOperand) and \
            emulator.get_operand_taint(curr_oprnd1) == False:

            # print "curr_oprnd1", curr_oprnd1, emulator.get_operand_taint(curr_oprnd1)

            value = emulator.read_operand(curr_oprnd1)
            new_oprnd1 = ReilImmediateOperand(value, curr_oprnd1.size)

            instruction.operands[1] = new_oprnd1

    return instruction

def process_binary(barf, args, ea_start, ea_end):
    """Executes the input binary and tracks Information about the
    branches that depends on input data.

    """
    print("[+] Executing x86 to REIL...")

    binary = barf.binary
    # args = prepare_inputs(barf.testcase["args"] + barf.testcase["files"])
    #args = input_file
    pcontrol = ProcessControl()

    process = pcontrol.start_process(binary, args, ea_start, ea_end, hooked_functions=["open", "fopen", "read", "fread"])

    #print "File: ", input_file[0]
    #with open(input_file[0], "r") as f:
    #    for l in f.readlines():
    #        print l
    #print "End of File."

    barf.ir_translator.reset()
    barf.smt_translator.reset()
    barf.code_analyzer.reset(full=True)

    ir_emulator = barf.ir_emulator
    c_analyzer = barf.code_analyzer
    c_analyzer.set_arch_info(barf.arch_info)

    native_platform = platform.machine()

    if native_platform == 'i386':
        host_arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    if native_platform == 'i686':
        host_arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    elif native_platform == 'x86_64':
        host_arch_info = X86ArchitectureInformation(ARCH_X86_MODE_64)
    else:
        print("[-] Error executing at platform '%s'" % native_platform)
        exit(-1)

    registers = barf.arch_info.registers_gp_base
    mapper = host_arch_info.alias_mapper

    branches_taint_data = []
    tainted_instrs = []
    concrete_tainted_instrs = []
    initial_taints = []
    addrs_to_vars = defaultdict(lambda: [])
    open_files = {}
    file_mem_mapper = {}
    addrs_to_file = {}

    # Continue until the first hooked function.
    event = pcontrol.cont()

    taint_read(process, event, ir_emulator, initial_taints, open_files, file_mem_mapper, addrs_to_file)

    ir_emulator._process = process
    ir_emulator._flags = barf.arch_info.registers_flags

    while pcontrol:
        # Get some bytes from current IP.
        addr = process.getInstrPointer()

        # Disassemble current native instruction.
        asm_instr = barf.disassembler.disassemble(process.readBytes(addr, 15), addr)

        #print("0x{0:08x} : {1}".format(addr, asm_instr))

        # Translate native instruction to REIL.
        reil_instrs = barf.ir_translator.translate(asm_instr)

        # Set REIL emulator context.
        ir_emulator.context = pcontrol.get_context(registers, mapper)

        # Process REIL instructions.
        for reil_instr in reil_instrs:
            # print("{0:14}{1}".format("", reil_instr))

            # If not supported, skip...
            if reil_instr.mnemonic == ReilMnemonic.UNKN:
                continue

            # Execute REIL instruction
            ir_emulator.execute_lite([reil_instr])

            # Add instructions with tainted operands to a list.
            #print reil_instr.operands

            if len(get_tainted_operands(reil_instr, ir_emulator)) > 0:
                if reil_instr.mnemonic not in [ReilMnemonic.LDM]:
                    concrete_instr = concretize_instruction(reil_instr, ir_emulator)

                    tainted_instrs.append(concrete_instr)

            #print tainted_instrs

            # Pair registers names with tainted memory addresses.
            if reil_instr.mnemonic == ReilMnemonic.LDM and \
                isinstance(reil_instr.operands[0], ReilRegisterOperand):

                oprnd = reil_instr.operands[0]

                addr = ir_emulator.read_operand(oprnd)
                size = reil_instr.operands[2].size

                if ir_emulator.get_memory_taint(addr, size):
                    oprnd_new = ReilRegisterOperand(oprnd.name + "_" + str(addr), oprnd.size)

                    reil_instr.operands[0] = oprnd_new

                    tainted_instrs.append(reil_instr)

                    addrs_to_vars[addr].append((oprnd_new, size))

            # If there is a conditional jump depending on tainted data
            # generate condition.
            if reil_instr.mnemonic == ReilMnemonic.JCC and \
                isinstance(reil_instr.operands[0], ReilRegisterOperand):

                cond = reil_instr.operands[0]

                if ir_emulator.get_operand_taint(cond):
                    print("[+] Tainted JCC")

                    cond_value = ir_emulator.read_operand(cond)

                    branches_taint_data.append({
                        'branch_address' : addr,
                        'tainted_instructions' : list(tainted_instrs),
                        'concrete_tainted_instructions' : list(concrete_tainted_instrs),
                        'branch_condition_register' : cond,
                        'branch_condition_value' : cond_value,
                        'initial_taints' : list(initial_taints),
                        'addrs_to_vars' : dict(addrs_to_vars),
                        'open_files' : dict(open_files),
                        'file_mem_mapper' : dict(file_mem_mapper),
                        'addrs_to_file' : dict(addrs_to_file),
                    })

        event = pcontrol.single_step()

        taint_read(process, event, ir_emulator, initial_taints, open_files, file_mem_mapper, addrs_to_file)


        if isinstance(event, ProcessExit):
            print("[+] Process exit.")
            break

        if isinstance(event, ProcessEnd):
            print("[+] Process end.")
            break

    process.terminate()

    return branches_taint_data

def main(args):
    """Main function.
    """
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

    #input_files = []

    inputs = prepare_inputs(barf.testcase["args"] + barf.testcase["files"])
    branches_taint_data = process_binary(barf, inputs, ea_start, ea_end)
    new_raw_files = analyze_tainted_branch_data(barf.code_analyzer, branches_taint_data, 0)
    new_files = map(lambda args: File(*args), new_raw_files)

    map(add_to_explore, zip(branches_taint_data, new_files))

    while new_to_explore():

        branch, input_file = next_to_explore()
        inputs = prepare_inputs(barf.testcase["args"] + [input_file])
        branches_taint_data = process_binary(barf, inputs, ea_start, ea_end)
        new_raw_files = analyze_tainted_branch_data(barf.code_analyzer, branches_taint_data, 0)

        for (branch, raw_file) in zip(branches_taint_data, new_raw_files):
          if not was_explored(branch):
              add_to_explore( (branch, File(*raw_file)) )

        time.sleep(10)


if __name__ == "__main__":
    # NOTES:
    # 1. For now, it works only for programs compiled in 32 bits.
    # 2. For now, it only taints data from the 'read' function.
    # 3. For now, you have to HARDCODE the 'read' function address for
    # each binary.

    if open("/proc/sys/kernel/randomize_va_space").read().strip() <> "0":
        print "Address space layout randomization (ASLR) is enabled, disable it before continue"
        print "Hint: # echo 0 > /proc/sys/kernel/randomize_va_space"
        sys.exit(-1)

    main(dict(enumerate(sys.argv)))
