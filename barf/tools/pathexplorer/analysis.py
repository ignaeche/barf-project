from __future__ import print_function

import logging
import os

from barf.core.dbg.input import File

from barf.core.reil import ReilMnemonic
from barf.core.reil import ReilRegisterOperand

logger = logging.getLogger(__name__)


def is_conditional_jump(instr):
    return  instr.mnemonic == ReilMnemonic.JCC and \
            isinstance(instr.operands[0], ReilRegisterOperand)

def generate_input_files(c_analyzer, trace, trace_idx, mem_exprs, open_files):
    # generate a new copy of each open file
    new_inputs = []

    for fd in open_files:
        # Read 'master' file.
        filename = open_files[fd]['filename']

        with open(filename, "rb") as f:
            file_content = bytearray(f.read())

        # Generate new file name.
        full_name, extension = filename.split(".")
        base_name = full_name.split("_", 1)[0]

        new_filename = base_name + "_%03d" % (trace_idx) + "." + extension

        # Write new file.
        print("    [+] Generating new input file: %s" % new_filename)

        with open(new_filename, "wb") as f:
            f.write(file_content)

    for fd in open_files:
        # Read 'master' file.
        filename = open_files[fd]['filename']

        # Generate new file name.
        full_name, extension = filename.split(".")
        base_name = full_name.split("_", 1)[0]

        new_filename = base_name + "_%03d" % (trace_idx) + "." + extension

        with open(new_filename, "rb") as f:
            file_content = bytearray(f.read())

        # Write new file.
        print("    [+] Mutating new input file: %s" % new_filename)

        # Mutate file content.
        for instr, data, _ in trace:
            if instr.mnemonic == ReilMnemonic.LDM:
                addr_tainted = data["address"]

                value = c_analyzer.get_expr_value(mem_exprs[addr_tainted])

                for addr2 in sorted(data["file_data"].keys()):
                    fd2, off2 = data["file_data"][addr2]

                    if fd2 != fd:
                        break

                    addr_off = addr2 - addr_tainted

                    file_content[off2] = (value >> (addr_off * 8)) & 0xff

        with open(new_filename, "wb") as f:
            f.write(file_content)

    for fd in open_files:
        # Read 'master' file.
        filename = open_files[fd]['filename']

        # Generate new file name.
        full_name, extension = filename.split(".")
        base_name = full_name.split("_", 1)[0]

        new_filename = base_name + "_%03d" % (trace_idx) + "." + extension

        with open(new_filename, "rb") as f:
            file_content = bytearray(f.read())

        print("    [+] New input file content: {}".format(file_content))

        # TODO: Why is it filename and not new_filename? It's confusing.
        new_inputs.append((filename, file_content))

    return new_inputs

def check_path(exploration, trace, trace_id, branch_data):
    branch_index = branch_data["index"]
    branch_val = branch_data["value"]

    explored_trace = list(trace_id)

    explored_trace.append((trace[branch_index][0].address, branch_val == 0x0))
    trace_id.append((trace[branch_index][0].address, not branch_val == 0x0))

    exploration.add_to_explored(explored_trace)

    if exploration.was_explored(trace_id) or \
        exploration.will_be_explored(trace_id):
        return False

    return True

def print_analysis_result(c_analyzer, trace, trace_idx, branch_data, mem_exprs, testcase_dir, input_counter, new_inputs):
    branch_addr = branch_data["address"]
    branch_val = branch_data["value"]

    # Analyze path
    analysis_filename = testcase_dir + "/inputs/branch_analysis_%03d_%03d.txt" % (input_counter, trace_idx)
    analysis_file = open(analysis_filename, "w")

    print("    [+] Generating analysis file: %s" % os.path.basename(analysis_filename))

    # Print results.
    ruler = "# {0} #".format("=" * 76)
    title = "{ruler}\n# {{title}}\n{ruler}".format(ruler=ruler)

    # Branch Information
    print(title.format(title="Branch Information"), file=analysis_file)
    print("Branch number : %d" % trace_idx, file=analysis_file)
    print("Branch address : 0x%08x" % branch_addr, file=analysis_file)
    print("Branch taken? : %s" % (branch_val == 0x1), file=analysis_file)

    # Tainted Instructions
    print(title.format(title="Tainted Instructions"), file=analysis_file)
    for instr, _, _ in trace:
        print(instr, file=analysis_file)

    if c_analyzer.check() != 'sat':
        print("UnSat Constraints!!!", file=analysis_file)
        analysis_file.close()
        return

    # Memory State
    msg = "mem @ 0x{:08x} : {:x} ({:s})"
    print(title.format(title="Memory State"), file=analysis_file)
    for tainted_addr, mem_expr in sorted(mem_exprs.items()):
        value = c_analyzer.get_expr_value(mem_expr)

        value_str = ""
        for i in xrange(mem_expr.size / 8):
            value_str += chr((value >> (i * 8)) & 0xff)

        print(msg.format(tainted_addr, value, value_str), file=analysis_file)

    # New Input Files
    print(title.format(title="New Input Files"), file=analysis_file)

    # Print file name and content.
    for file_name, file_content in new_inputs:
        print("Name: %s" % file_name, file=analysis_file)
        print("Content: %s" % file_content, file=analysis_file)

    analysis_file.close()

	# Save SMT file.
    smt_filename = testcase_dir + "/inputs/smt_%03d_%03d.smt2" % (input_counter, trace_idx)

    print("    [+] Generating SMT file: %s" % os.path.basename(smt_filename))

    with open(smt_filename, "w") as smt_file:
        smt_file.write("{}\n".format("(set-logic QF_AUFBV)"))
        smt_file.write("{}\n".format(str(c_analyzer._solver)))
        smt_file.write("{}\n".format("(check-sat)"))

def get_conditional_branch_count(trace):
    branch_count = 0

    for instr, _, _ in trace:
        if is_conditional_jump(instr):
            branch_count += 1

    return branch_count

def get_last_branch_data(trace):
    branch_index = 0
    branch_count = get_conditional_branch_count(trace)

    branch_data = None

    for instr, data, timestamp in trace:
        if is_conditional_jump(instr):
            if branch_index == branch_count - 1:
                branch_data = dict(data)
                branch_data["index"] = branch_index
                branch_data["timestamp"] = timestamp
                break
            branch_index += 1

    return branch_data

def get_memory_expr(c_analyzer, trace):
    mem_exprs = {}

    for instr, data, _ in trace:
        if instr.mnemonic == ReilMnemonic.LDM and data:
            addr_tainted = data["address"]

            addr_expr = c_analyzer.get_operand_var(instr.operands[0])
            mem_expr = c_analyzer.get_memory_expr(addr_expr, instr.operands[2].size / 8, mode="pre")

            mem_exprs[addr_tainted] = mem_expr

    return mem_exprs

def add_trace_to_analyzer(c_analyzer, trace):
    branch_index = 0
    branch_count = get_conditional_branch_count(trace)

    for instr, data, _ in trace:
        if is_conditional_jump(instr):
            # Unpack branch data.
            branch_addr = data['address']
            branch_cond = data['condition']
            branch_val = data['value']

            if branch_index == branch_count - 1:
                break
            # DEBUG
            # taken = "taken" if branch_val else "not-taken"
            # print("Branch : {:#x} ({})".format(branch_addr, taken))

            oprnd0_var = c_analyzer.get_operand_var(instr.operands[0])
            c_analyzer.add_constraint(oprnd0_var == branch_val)

            branch_index += 1
        else:
            c_analyzer.add_instruction(instr)

    # Get a SMT variable for the branch condition.
    branch_cond_var = c_analyzer.get_operand_expr(branch_cond, mode="post")

    # DEBUG
    # taken = "taken" if branch_val else "not-taken"
    # taken2 = "not-taken" if branch_val else "taken"
    # print("Branch : {:#x} ({} -> {})".format(branch_addr, taken, taken2))

    # Set wanted branch condition.
    c_analyzer.set_postcondition(branch_cond_var != branch_val)

def generate_trace_id(trace):
    branch_index = 0
    branch_count = get_conditional_branch_count(trace)

    trace_id = []

    for instr, data, _ in trace:
        if is_conditional_jump(instr):
            # Unpack branch data.
            branch_val = data['value']

            if branch_index == branch_count - 1:
                break

            trace_id.append((instr.address, branch_val == 0x0))

            branch_index += 1

    return trace_id

def generate_subtraces(trace):
    subtraces = []
    trace_curr = []

    for data in trace:
        trace_curr.append(data)

        if is_conditional_jump(data[0]):
            subtraces.append(list(trace_curr))

    return subtraces

def analyze_trace(exploration, c_analyzer, trace_data, testcase_dir, input_idx):
    """For each input branch (which depends on tainted input), it
    prints the values needed to avoid taking that branch.

    """
    print("[+] Start trace analysis...")

    # TODO: Remove superfluous instructions from the trace.
    trace = trace_data['trace']
    open_files = trace_data['open_files']
    memory_taints = trace_data['memory_taints']

    branch_count = get_conditional_branch_count(trace)

    print("  [+] Total tainted branches : %d" % branch_count)

    for subtrace_idx, subtrace in enumerate(generate_subtraces(trace)):
        logger.info("Branch analysis #{}".format(subtrace_idx))

        print("  [+] Analysis branch: {}".format(subtrace_idx))

        c_analyzer.reset(full=True)

        # Get last branch data.
        branch_data = get_last_branch_data(subtrace)

        # Add initial tainted addresses to the code analyzer.
        mem_exprs = get_memory_expr(c_analyzer, subtrace)

        # Add instructions to the code analyzer.
        add_trace_to_analyzer(c_analyzer, subtrace)

        # Check whether explore this path or not.
        subtrace_id = generate_trace_id(subtrace)

        if not check_path(exploration, subtrace, subtrace_id, branch_data):
            print("    [+] Ignoring path...")
            continue

        if c_analyzer.check() == 'sat':
            new_inputs = generate_input_files(c_analyzer, subtrace, subtrace_idx, mem_exprs, open_files)

            exploration.add_to_explore((subtrace_id, File(*new_inputs[0])))

            # Print results
            print_analysis_result(c_analyzer, subtrace, subtrace_idx, branch_data, mem_exprs, testcase_dir, input_idx, new_inputs)
        else:
            print("    [+] Unsatisfiable path...")

            exploration.add_to_explored(subtrace_id)

    print("{0}\n{0}".format("~" * 80))
