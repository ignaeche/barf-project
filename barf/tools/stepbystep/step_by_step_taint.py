#!/usr/bin/env python

import logging
import os
import platform
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

from barf.core.dbg.event import Call

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

        # Generate new input file.
        for fd in open_files:
            filename = open_files[fd]['filename']

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

            print "file content: ", file_content

            name, extension = filename.split(".")
            name = name.split("_", 1)[0]

            new_filename = name + "_%03d_%03d" % (iteration, idx) + "." + extension

            with open(new_filename, "wb") as f:
                f.write(file_content)

            new_inputs.append(new_filename)

    return new_inputs

def taint_read(process, event, ir_emulator, initial_taints, open_files, file_mem_mapper, addrs_to_file):
    if isinstance(event, Call):
        if event.name == "open":
            pathname_ptr, _ = event.get_typed_parameters()[0]
            file_desc = event.return_value

            # TODO: Get filename.
            i = 0
            maxcnt = 1024
            filename = ""
            byte = process.readBytes(pathname_ptr+i, 1)
            while byte != "\x00" and len(filename) < maxcnt:
                filename += byte
                i += 1
                byte = process.readBytes(pathname_ptr+i, 1)

            open_files[file_desc] = {
                'filename' : filename,
                'f_pos' : 0
            }

        if event.name == "read":
            file_desc, _ = event.get_typed_parameters()[0]
            buf, _ = event.get_typed_parameters()[1]
            bytes_read = event.return_value

            file_curr_pos = open_files[file_desc]['f_pos']
            fmapper = file_mem_mapper.get(file_desc, {})

            # Taint memory address.
            ir_emulator.set_memory_taint(buf, bytes_read * 8, True)

            # Keep record of inital taints.
            for i in xrange(0, bytes_read):
                fmapper[buf + i] = file_curr_pos + i
                initial_taints.append(buf + i)

                d_entry = addrs_to_file.get(buf + i, {})
                l_entry = d_entry.get(file_desc, [])
                l_entry.append(file_curr_pos + i)

                d_entry[file_desc] = l_entry
                addrs_to_file[buf + i] = d_entry

            open_files[file_desc]['f_pos'] = bytes_read
            file_mem_mapper[file_desc] = fmapper

def process_binary(barf, input_file, ea_start, ea_end):
    """Executes the input binary and tracks Information about the
    branches that depends on input data.

    """
    print("[+] Executing x86 to REIL...")

    binary = barf.binary
    # args = prepare_inputs(barf.testcase["args"] + barf.testcase["files"])
    args = input_file
    pcontrol = ProcessControl()

    process = pcontrol.start_process(binary, args, ea_start, ea_end, hooked_functions=["open", "read"])

    ir_emulator = barf.ir_emulator
    c_analyzer = barf.code_analyzer
    c_analyzer.set_arch_info(barf.arch_info)

    native_platform = platform.machine()

    if native_platform == 'i386': 
        arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    if native_platform == 'i686':  
        arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    elif native_platform == 'x86_64':
        arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
    else:
        print("[-] Error executing at platform '%s'" % native_platform)
        exit(-1)



    registers = arch_info.registers_gp_base
    mapper = arch_info.registers_access_mapper()

    branches_taint_data = []
    tainted_instrs = []
    initial_taints = []
    addrs_to_vars = defaultdict(lambda: [])
    open_files = {}
    file_mem_mapper = {}
    addrs_to_file = {}

    # Continue until the first hooked function.
    event = pcontrol.cont()

    taint_read(process, event, ir_emulator, initial_taints, open_files, file_mem_mapper, addrs_to_file)

    while pcontrol:
        # Get some bytes from current IP.
        addr = process.getInstrPointer()

        # Disassemble current native instruction.
        asm_instr = barf.disassembler.disassemble(process.readBytes(addr, 15), addr)

        print("0x{0:08x} : {1}".format(addr, asm_instr))

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
                tainted_instrs.append(reil_instr)
 
            #print tainted_instrs

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
                    print("[+] Tainted JCC")

                    cond_value = ir_emulator.read_operand(cond)

                    branches_taint_data.append({
                        'branch_address' : addr,
                        'tainted_instructions' : list(tainted_instrs),
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

    input_files = []

    input_file = prepare_inputs(barf.testcase["args"] + barf.testcase["files"])

    input_files.append(input_file[0])

    iteration = 0

    while input_files and iteration < 10:
        input_file = input_files.pop()

        print "Processing #%d: %s" % (iteration, input_file)

        branches_taint_data = process_binary(barf, [input_file], ea_start, ea_end)

        new_inputs = analyze_tainted_branch_data(barf.code_analyzer, branches_taint_data, iteration)

        input_files.extend(new_inputs)

        iteration += 1


if __name__ == "__main__":
    # NOTES:
    # 1. For now, it works only for programs compiled in 32 bits.
    # 2. For now, it only taints data from the 'read' function.
    # 3. For now, you have to HARDCODE the 'read' function address for
    # each binary.

    main(dict(enumerate(sys.argv)))
