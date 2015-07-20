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


def concretize_instruction(emu, instr):
    if instr.mnemonic not in [ReilMnemonic.LDM]:

        oprnd0, _, oprnd1 = instr.operands

        if isinstance(oprnd0, ReilRegisterOperand) and \
            not isinstance(oprnd0, ReilEmptyOperand) and \
            emu.get_operand_taint(oprnd0) == False:

            value = emu.read_operand(oprnd0)
            oprnd0_new = ReilImmediateOperand(value, oprnd0.size)

            instr.operands[0] = oprnd0_new

        elif isinstance(oprnd1, ReilRegisterOperand) and \
            not isinstance(oprnd1, ReilEmptyOperand) and \
            emu.get_operand_taint(oprnd1) == False:

            value = emu.read_operand(oprnd1)
            oprnd1_new = ReilImmediateOperand(value, oprnd1.size)

            instr.operands[1] = oprnd1_new

    return instr

def process_reil_instruction(emu, instr, trace, addrs_to_vars):
    oprnd0, _, oprnd2 = instr.operands

    timestamp = int(time.time())

    if instr.mnemonic == ReilMnemonic.LDM:
        addr = emu.read_operand(oprnd0)
        size = oprnd2.size

        if emu.get_memory_taint(addr, size):
            if isinstance(oprnd0, ReilRegisterOperand):
                reg_name = oprnd0.name + "_" + str(addr)
                oprnd0_new = ReilRegisterOperand(reg_name, oprnd0.size)

                instr.operands[0] = oprnd0_new

                addrs_to_vars[addr].append((oprnd0_new, size, timestamp))

            trace.append((instr, None, timestamp))
    elif instr.mnemonic == ReilMnemonic.JCC:
        # Consider only conditional jumps, discard direct ones.
        if isinstance(oprnd0, ReilRegisterOperand):
            if emu.get_operand_taint(oprnd0):
                address = instr.address >> 0x8

                print("  [+] Tainted JCC found @ 0x%08x" % address)

                data = {
                    'address' : address,
                    'condition' : oprnd0,
                    'value' : emu.read_operand(oprnd0)
                }

                trace.append((instr, data, timestamp))
    else:
        # If there are tainted operands, add instruction to the trace.
        if any([emu.get_operand_taint(o) for o in instr.operands]):
            instr_concrete = concretize_instruction(emu, instr)

            trace.append((instr_concrete, None, timestamp))

def instr_pre_handler(emu, instr, process):
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
    barf.ir_emulator.set_instruction_pre_handler(instr_pre_handler, process)

    emu = barf.ir_emulator

    trace = []
    open_files = {}
    memory_taints = []
    addrs_to_vars = defaultdict(lambda: [])
    addrs_to_files = {}

    print("[+] Start process tracing...")
    # Continue until the first taint
    while True:
        event = pcontrol.cont()

        if process_event(process, event, emu, memory_taints, open_files, addrs_to_files):
            break

    # Start processing trace
    while pcontrol:
        ip = process.getInstrPointer()
        asm_instr = barf.disassembler.disassemble(process.readBytes(ip, 15), ip)

        # Set REIL emulator context.
        emu.registers = pcontrol.get_registers()

        # Process REIL instructions.
        #print("0x{0:08x} : {1}".format(ip, asm_instr))

        for reil_instr in barf.ir_translator.translate(asm_instr):
            # print("{0:14}{1}".format("", reil_instr))

            # If not supported, skip...
            if reil_instr.mnemonic == ReilMnemonic.UNKN:
                continue

            emu.execute_lite([reil_instr])

            process_reil_instruction(emu, reil_instr, trace, addrs_to_vars)

        event = pcontrol.single_step()

        process_event(process, event, emu, memory_taints, open_files, addrs_to_files)

        if isinstance(event, ProcessExit):
            print("  [+] Process exit.")
            break

        if isinstance(event, ProcessEnd):
            print("  [+] Process end.")
            break

    process.terminate()

    branches_taint_data = {
        'trace' : trace,
        'memory_taints' : memory_taints,
        'addrs_to_vars' : addrs_to_vars,
        'open_files' : open_files,
        'addrs_to_files' : addrs_to_files,
    }

    return branches_taint_data
