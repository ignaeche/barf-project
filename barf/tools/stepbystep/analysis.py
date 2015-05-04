from __future__ import print_function

import logging

from barf.core.dbg.input import File

from barf.core.reil import ReilMnemonic
from barf.core.reil import ReilRegisterOperand

logger = logging.getLogger(__name__)

def generate_input_files(c_analyzer, mem_exprs, open_files, addrs_to_files, iteration, branch_index, analysis_file):
    new_inputs = []

    for fd in open_files:
        # Read 'master' file.
        filename = open_files[fd]['filename']

        with open(filename, "rb") as f:
            file_content = bytearray(f.read())

        # Mutate file content.
        for tainted_addr, mem_expr in sorted(mem_exprs.items()):
            for pos in addrs_to_files[tainted_addr].get(fd, []):
                file_content[pos] = c_analyzer.get_expr_value(mem_expr)

        # Write new file.
        full_name, extension = filename.split(".")
        base_name = full_name.split("_", 1)[0]

        new_filename = base_name + "_%03d_%03d" % (iteration, branch_index) + "." + extension

        with open(new_filename, "wb") as f:
            f.write(file_content)

        # Print new file name and content.
        print("Name: %s" % new_filename, file=analysis_file)
        print("Content: %s" % file_content, file=analysis_file)

        print("[+] Generating input file: %s" % new_filename)

        new_inputs.append((filename, file_content))

    return new_inputs

def analyze_tainted_branch_data(exploration, c_analyzer, branches_taint_data, iteration, testcase_dir, input_counter):
    """For each input branch (which depends on tainted input), it
    prints the values needed to avoid taking that branch.

    """
    print("[+] Total branches : %d" % len(branches_taint_data))

    for idx, branch_taint_data in enumerate(branches_taint_data):
        logger.info("Branch analysis #{}".format(idx))

        c_analyzer.reset(full=True)

        # TODO: Simplify tainted instructions, i.e, remove superfluous
        # instructions.
        branch_addr = branch_taint_data['branch_address']
        branch_cond = branch_taint_data['branch_condition_register']
        branch_val = branch_taint_data['branch_condition_value']

        instrs_list = branch_taint_data['tainted_instructions']

        open_files = branch_taint_data['open_files']

        initial_taints = branch_taint_data['initial_taints']

        addrs_to_vars = branch_taint_data['addrs_to_vars']
        addrs_to_files = branch_taint_data['addrs_to_files']

        # Add initial tainted addresses to the code analyzer.
        mem_exprs = {}

        for tainted_addr in initial_taints:
            for reg, access_size in addrs_to_vars.get(tainted_addr, []):
                addr_expr = c_analyzer.get_operand_var(reg)
                mem_expr = c_analyzer.get_memory_expr(
                                addr_expr, access_size / 8, mode="pre")

                mem_exprs[tainted_addr] = mem_expr

        # Add instructions to the code analyzer.
        jcc_index = 0
        trace_id = []

        for instr in instrs_list[:-1]:
            #print hex(instr.address), instr
            if instr.mnemonic == ReilMnemonic.JCC and \
                isinstance(instr.operands[0], ReilRegisterOperand):
                op1_var = c_analyzer.get_operand_var(instr.operands[0])

                jcc_cond_val = branch_val[jcc_index]

                c_analyzer.add_constraint(op1_var == jcc_cond_val)
                trace_id.append((instr.address, jcc_cond_val == 0x0))

                jcc_index += 1

            c_analyzer.add_instruction(instr)

        # Get a SMT variable for the branch condition.
        branch_cond_var = c_analyzer.get_operand_expr(branch_cond, mode="post")

        # Set wanted branch condition.
        c_analyzer.set_postcondition(branch_cond_var != branch_val[jcc_index])

        explored_trace = list(trace_id)
        to_explore_trace = list(trace_id)

        explored_trace.append((instrs_list[-1].address, branch_val[jcc_index] == 0x0))
        to_explore_trace.append((instrs_list[-1].address, not(branch_val[jcc_index] == 0x0)))

        exploration.add_to_explored(explored_trace)

        if exploration.was_explored(to_explore_trace) or exploration.will_be_explored(to_explore_trace):
            continue

        analysis_filename = testcase_dir + "/crash/branch_analysis_%03d_%03d_%03d.txt" % (input_counter, iteration, idx)
        analysis_file = open(analysis_filename, "w")
        print("[+] Generating analysis file: %s" % analysis_filename)

        # Print results.
        ruler = "# {0} #".format("=" * 76)
        title = "{ruler}\n# {{title}}\n{ruler}".format(ruler=ruler)
        footer = "{0}\n{0}".format("~" * 80)

        # Branch Information
        print(title.format(title="Branch Information"), file=analysis_file)
        print("Branch number : %d" % idx, file=analysis_file)
        print("Branch address : 0x%08x" % branch_addr, file=analysis_file)
        print("Branch taken? : %s" % (branch_val == 0x1), file=analysis_file)

        # Tainted Instructions
        print(title.format(title="Tainted Instructions"), file=analysis_file)
        for instr in instrs_list:
            print(instr, file=analysis_file)

        if c_analyzer.check() != 'sat':
            print("UnSat Constraints!!!", file=analysis_file)
            exploration.add_to_explored(to_explore_trace)
            print(footer, file=analysis_file)

            analysis_file.close()
            continue

        # Memory State
        msg = "mem @ 0x{:08x} : {:02x} ({:s})"
        print(title.format(title="Memory State"), file=analysis_file)
        for tainted_addr, mem_expr in sorted(mem_exprs.items()):
            value = c_analyzer.get_expr_value(mem_expr)

            print(msg.format(tainted_addr, value, chr(value)), file=analysis_file)

        # New Input Files
        print(title.format(title="New Input Files"), file=analysis_file)
        new_input = generate_input_files(c_analyzer, mem_exprs, open_files, addrs_to_files, iteration, idx, analysis_file)
        exploration.add_to_explore((to_explore_trace, File(*new_input[0])))

        print(footer)

        analysis_file.close()
