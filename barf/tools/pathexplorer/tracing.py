from __future__ import print_function

import logging
import time

from collections import defaultdict

from barf.core.dbg.debugger import ProcessControl
from barf.core.dbg.debugger import ProcessEnd
from barf.core.dbg.debugger import ProcessExit
from barf.core.reil import ReilEmptyOperand
from barf.core.reil import ReilImmediateOperand
from barf.core.reil import ReilMnemonic
from barf.core.reil import ReilRegisterOperand

from hooks import process_event

logger = logging.getLogger(__name__)


def concretize_instruction(instruction, emulator):
    if instruction.mnemonic not in [ReilMnemonic.LDM]:

        curr_oprnd0 = instruction.operands[0]
        curr_oprnd1 = instruction.operands[1]

        if isinstance(curr_oprnd0, ReilRegisterOperand) and \
            not isinstance(curr_oprnd0, ReilEmptyOperand) and \
            emulator.get_operand_taint(curr_oprnd0) == False:

            value = emulator.read_operand(curr_oprnd0)
            new_oprnd0 = ReilImmediateOperand(value, curr_oprnd0.size)

            instruction.operands[0] = new_oprnd0

        elif isinstance(curr_oprnd1, ReilRegisterOperand) and \
            not isinstance(curr_oprnd1, ReilEmptyOperand) and \
            emulator.get_operand_taint(curr_oprnd1) == False:

            value = emulator.read_operand(curr_oprnd1)
            new_oprnd1 = ReilImmediateOperand(value, curr_oprnd1.size)

            instruction.operands[1] = new_oprnd1

    return instruction

def process_reil_instruction(emulator, instr, trace, addrs_to_vars):
    oprnd0, _, oprnd2 = instr.operands

    timestamp = int(time.time())

    if instr.mnemonic == ReilMnemonic.LDM:
        if isinstance(oprnd0, ReilRegisterOperand):
            addr = emulator.read_operand(oprnd0)
            size = oprnd2.size

            if emulator.get_memory_taint(addr, size):
                reg_name = oprnd0.name + "_" + str(addr)
                oprnd_new = ReilRegisterOperand(reg_name, oprnd0.size)
                instr.operands[0] = oprnd_new

                addrs_to_vars[addr].append((oprnd_new, size, timestamp))

                trace.append((instr, None, timestamp))
    elif instr.mnemonic == ReilMnemonic.JCC:
        if isinstance(oprnd0, ReilRegisterOperand):
            if emulator.get_operand_taint(oprnd0):
                address = instr.address >> 0x8

                print("  [+] Tainted JCC found @ 0x%08x" % address)

                data = {
                    'address' : address,
                    'condition' : oprnd0,
                    'value' : emulator.read_operand(oprnd0)
                }

                trace.append((instr, data, timestamp))
    else:
        oprnds_taint = [emulator.get_operand_taint(oprnd)
                            for oprnd in instr.operands]

        if any(oprnds_taint):
            concrete_instr = concretize_instruction(instr, emulator)

            trace.append((concrete_instr, None, timestamp))

def instr_pre_hanlder(emu, instr, process):
    if instr.mnemonic == ReilMnemonic.LDM:
        base_addr = emu.read_operand(instr.operands[0])

        for i in xrange(0, instr.operands[2].size / 8):
            addr = base_addr + i

            if not emu.memory.written(addr):
                try:
                    emu.write_memory(addr, 1, ord(process.readBytes(addr, 1)))
                except:
                    logger.info("Error reading process memory @ 0x{:08x}".format(addr))

def process_binary(barf, args, ea_start, ea_end):
    """Executes the input binary and tracks Information about the
    branches that depends on input data.

    """
    pcontrol = ProcessControl()
    hooked_functions = ["open", "read"]

    process = pcontrol.start_process(barf.binary, args, ea_start, ea_end, hooked_functions)

    barf.ir_translator.reset()

    emulator = barf.ir_emulator
    emulator.set_instruction_pre_handler(instr_pre_hanlder, process)

    trace = []
    open_files = {}
    initial_taints = []
    addrs_to_vars = defaultdict(lambda: [])
    addrs_to_files = {}

    print("[+] Start process tracing...")
    # Continue until the first taint
    while True:
        event = pcontrol.cont()

        if process_event(process, event, emulator, initial_taints, open_files, addrs_to_files):
            break

    # Start processing trace
    while pcontrol:
        ip = process.getInstrPointer()
        asm_instr = barf.disassembler.disassemble(process.readBytes(ip, 15), ip)

        # Set REIL emulator context.
        emulator.registers = pcontrol.get_registers()

        # Process REIL instructions.
        #print("0x{0:08x} : {1}".format(ip, asm_instr))

        for reil_instr in barf.ir_translator.translate(asm_instr):
            # print("{0:14}{1}".format("", reil_instr))

            # If not supported, skip...
            if reil_instr.mnemonic == ReilMnemonic.UNKN:
                continue

            emulator.execute_lite([reil_instr])

            process_reil_instruction(emulator, reil_instr, trace, addrs_to_vars)

        event = pcontrol.single_step()

        process_event(process, event, emulator, initial_taints, open_files, addrs_to_files)

        if isinstance(event, ProcessExit):
            print("  [+] Process exit.")
            break

        if isinstance(event, ProcessEnd):
            print("  [+] Process end.")
            break

    process.terminate()

    branches_taint_data = {
        'trace' : trace,
        'initial_taints' : initial_taints,
        'addrs_to_vars' : addrs_to_vars,
        'open_files' : open_files,
        'addrs_to_files' : addrs_to_files,
    }

    return branches_taint_data
