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
    oprnd0, oprnd1, _ = instr.operands

    if instr.mnemonic == ReilMnemonic.LDM:
        if isinstance(oprnd0, ReilRegisterOperand):
            addr = emu.read_operand(oprnd0)
            name = "{0}_{1:x}".format(oprnd0.name, addr)

            instr.operands[0] = ReilRegisterOperand(name, oprnd0.size)
    else:
        if isinstance(oprnd0, ReilRegisterOperand) and \
            not isinstance(oprnd0, ReilEmptyOperand) and \
            not emu.get_operand_taint(oprnd0):

            value = emu.read_operand(oprnd0)

            instr.operands[0] = ReilImmediateOperand(value, oprnd0.size)

        elif isinstance(oprnd1, ReilRegisterOperand) and \
            not isinstance(oprnd1, ReilEmptyOperand) and \
            not emu.get_operand_taint(oprnd1):

            value = emu.read_operand(oprnd1)

            instr.operands[1] = ReilImmediateOperand(value, oprnd1.size)

    return instr

def process_reil_instruction(emu, instr, trace, memory_taints):
    oprnd0, _, oprnd2 = instr.operands

    timestamp = int(time.time())

    if instr.mnemonic == ReilMnemonic.LDM:
        addr = emu.read_operand(oprnd0)
        size = oprnd2.size / 8

        if emu.get_memory_taint(addr, size):
            instr_concrete = concretize_instruction(emu, instr)

            data = {
                "address" : addr,
                "file_data" : {},
            }

            for i in xrange(0, size):
                addr2 = addr + i

                if addr2 in memory_taints:
                    data["file_data"][addr2] = memory_taints[addr2]

            trace.append((instr_concrete, data, timestamp))
    elif instr.mnemonic == ReilMnemonic.JCC:
        # Consider only conditional jumps, discard direct ones.
        if isinstance(oprnd0, ReilRegisterOperand):
            if emu.get_operand_taint(oprnd0):
                address = instr.address >> 0x8
                value = emu.read_operand(oprnd0)
                result = "taken" if value != 0 else "not taken"

                print("  [+] Tainted JCC found @ {:#x} ({})".format(address, result))

                data = {
                    'address' : address,
                    'condition' : oprnd0,
                    'value' : value
                }

                trace.append((instr, data, timestamp))
    else:
        # If the instruction has at least a tainted operand, add it
        # to the trace.
        if any([emu.get_operand_taint(o) for o in instr.operands]):
            instr_concrete = concretize_instruction(emu, instr)

            trace.append((instr_concrete, None, timestamp))

def instr_pre_handler(emu, instr, process):
    if instr.mnemonic == ReilMnemonic.LDM:
        # Set emulator memory in case it hasn't been set previously.
        base_addr = emu.read_operand(instr.operands[0])

        for i in xrange(0, instr.operands[2].size / 8):
            addr = base_addr + i

            if not emu.memory.written(addr):
                try:
                    emu.write_memory(addr, 1, ord(process.readBytes(addr, 1)))
                except:
                    logger.info("Error reading process memory @ 0x{:08x}".format(addr))

def trace_program(barf, args, ea_start, ea_end):
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
    memory_taints = {}

    print("[+] Start process tracing...")

    # Continue until the first taint
    while True:
        event = pcontrol.cont()

        if process_event(process, event, emu, memory_taints, open_files):
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

            process_reil_instruction(emu, reil_instr, trace, memory_taints)

        event = pcontrol.single_step()

        process_event(process, event, emu, memory_taints, open_files)

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
        'open_files' : open_files,
    }

    return branches_taint_data
