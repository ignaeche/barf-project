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

def generate_input_files(c_analyzer, mem_exprs, open_files, addrs_to_files, iteration, branch_index):
    new_inputs = []

    for fd in open_files:
        # Read 'master' file.
        filename = open_files[fd]['filename']

        with open(filename, "rb") as f:
            file_content = bytearray(f.read())

        # Mutate file content.
        for tainted_addr, mem_expr in sorted(mem_exprs.items()):
            if tainted_addr not in addrs_to_files:
                continue

            for pos in addrs_to_files[tainted_addr].get(fd, []):
                file_content[pos] = c_analyzer.get_expr_value(mem_expr)

        # Generate new file name.
        full_name, extension = filename.split(".")
        base_name = full_name.split("_", 1)[0]

        new_filename = base_name + "_%03d_%03d" % (iteration, branch_index) + "." + extension

        # Write new file.
        print("    [+] Generating new input file: %s" % new_filename)

        with open(new_filename, "wb") as f:
            f.write(file_content)

        new_inputs.append((filename, file_content))

    return new_inputs

def check_path(exploration, instrs_list, trace_id, branch_val, jcc_index, to_explore_trace):
    explored_trace = list(trace_id)

    explored_trace.append((instrs_list[jcc_index][0].address, branch_val == 0x0))
    to_explore_trace.append((instrs_list[jcc_index][0].address, not branch_val == 0x0))

    exploration.add_to_explored(explored_trace)

    if exploration.was_explored(to_explore_trace) or exploration.will_be_explored(to_explore_trace):
        return False

    return True

def print_analysis_result(c_analyzer, testcase_dir, input_counter, iteration, idx, branch_addr, branch_val, instrs_list, mem_exprs, new_inputs):
    # Analyze path
    analysis_filename = testcase_dir + "/crash/branch_analysis_%03d_%03d_%03d.txt" % (input_counter, iteration, idx)
    analysis_file = open(analysis_filename, "w")

    print("    [+] Generating analysis file: %s" % os.path.basename(analysis_filename))

    # Print results.
    ruler = "# {0} #".format("=" * 76)
    title = "{ruler}\n# {{title}}\n{ruler}".format(ruler=ruler)

    # Branch Information
    print(title.format(title="Branch Information"), file=analysis_file)
    print("Branch number : %d" % idx, file=analysis_file)
    print("Branch address : 0x%08x" % branch_addr, file=analysis_file)
    print("Branch taken? : %s" % (branch_val == 0x1), file=analysis_file)

    # Tainted Instructions
    print(title.format(title="Tainted Instructions"), file=analysis_file)
    for instr, _, _ in instrs_list:
        print(instr, file=analysis_file)

    if c_analyzer.check() != 'sat':
        print("UnSat Constraints!!!", file=analysis_file)
        analysis_file.close()
        return

    # Memory State
    msg = "mem @ 0x{:08x} : {:02x} ({:s})"
    print(title.format(title="Memory State"), file=analysis_file)
    for tainted_addr, mem_expr in sorted(mem_exprs.items()):
        value = c_analyzer.get_expr_value(mem_expr)

        print(msg.format(tainted_addr, value, chr(value)), file=analysis_file)

    # New Input Files
    print(title.format(title="New Input Files"), file=analysis_file)

    # Print file name and content.
    for file_name, file_content in new_inputs:
        print("Name: %s" % file_name, file=analysis_file)
        print("Content: %s" % file_content, file=analysis_file)

    analysis_file.close()

def get_branch_count(trace):
    branch_count = 0

    for instr, _, _ in trace:
        if instr.mnemonic == ReilMnemonic.JCC and \
            isinstance(instr.operands[0], ReilRegisterOperand):
            branch_count += 1

    return branch_count

def get_last_branch_timestamp(trace):
    branch_index = 0
    branch_count = get_branch_count(trace)

    branch_timestamp = None

    for instr, _, timestamp in trace:
        if is_conditional_jump(instr):
            if branch_index == branch_count - 1:
                branch_timestamp = timestamp
                break
            branch_index += 1

    return branch_timestamp

def get_memory_expr(c_analyzer, memory_taints, addrs_to_vars, branch_timestamp):
    mem_exprs = {}

    for tainted_addr, timestamp in memory_taints:
        if timestamp > branch_timestamp:
            break

        for reg, access_size, timestamp2 in addrs_to_vars.get(tainted_addr, []):
            if timestamp2 > branch_timestamp:
                continue

            addr_expr = c_analyzer.get_operand_var(reg)
            mem_expr = c_analyzer.get_memory_expr(addr_expr, access_size / 8, mode="pre")

            mem_exprs[tainted_addr] = mem_expr

    return mem_exprs

def add_trace_to_analyzer(c_analyzer, trace):
    branch_index = 0
    branch_count = get_branch_count(trace)

    for instr, data, _ in trace:
        if is_conditional_jump(instr):
            # Unpack branch data.
            branch_addr = data['address']
            branch_cond = data['condition']
            branch_val = data['value']

            if branch_index == branch_count - 1:
                break

            oprnd0_var = c_analyzer.get_operand_var(instr.operands[0])
            c_analyzer.add_constraint(oprnd0_var == branch_val)

            branch_index += 1
        else:
            c_analyzer.add_instruction(instr)

    # Get a SMT variable for the branch condition.
    branch_cond_var = c_analyzer.get_operand_expr(branch_cond, mode="post")

    # Set wanted branch condition.
    c_analyzer.set_postcondition(branch_cond_var != branch_val)

    return branch_index, branch_addr, branch_cond, branch_val

def generate_trace_id(trace):
    branch_index = 0
    branch_count = get_branch_count(trace)

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

def analyze_tainted_branch_data(exploration, c_analyzer, branch_taint_data, iteration, testcase_dir, input_counter):
    """For each input branch (which depends on tainted input), it
    prints the values needed to avoid taking that branch.

    """
    print("[+] Start trace analysis...")

    # TODO: Simplify tainted instructions, i.e, remove superfluous
    # instructions.
    trace = branch_taint_data['trace']

    open_files = branch_taint_data['open_files']
    memory_taints = branch_taint_data['memory_taints']
    addrs_to_vars = branch_taint_data['addrs_to_vars']
    addrs_to_files = branch_taint_data['addrs_to_files']

    branch_count = get_branch_count(trace)

    print("  [+] Total tainted branches : %d" % branch_count)

    for idx, subtrace in enumerate(generate_subtraces(trace)):
        logger.info("Branch analysis #{}".format(idx))

        print("  [+] Analysis branch: {}".format(idx))

        c_analyzer.reset(full=True)

        # Get current branch timestamp.
        branch_timestamp = get_last_branch_timestamp(subtrace)

        # Add initial tainted addresses to the code analyzer.
        mem_exprs = get_memory_expr(c_analyzer, memory_taints, addrs_to_vars, branch_timestamp)

        # Add instructions to the code analyzer.
        branch_index, branch_addr, _, branch_val = add_trace_to_analyzer(c_analyzer, subtrace)

        # Check whether explore this path or not.
        trace_id = generate_trace_id(subtrace)

        to_explore_trace = list(trace_id)

        if not check_path(exploration, subtrace, trace_id, branch_val, branch_index, to_explore_trace):
            print("    [+] Ignoring path...")
            continue

        if c_analyzer.check() != 'sat':
            new_inputs = []
            exploration.add_to_explored(to_explore_trace)
        else:
            new_inputs = generate_input_files(c_analyzer, mem_exprs, open_files, addrs_to_files, iteration, idx)
            exploration.add_to_explore((to_explore_trace, File(*new_inputs[0])))

        # Print results
        print_analysis_result(c_analyzer, testcase_dir, input_counter, iteration, idx, branch_addr, branch_val, subtrace, mem_exprs, new_inputs)

    print("{0}\n{0}".format("~" * 80))
