#!/usr/bin/env python
from __future__ import print_function

import logging
import os
import sys

from barf import BARF

from barf.core.dbg.testcase import prepare_inputs

from exploration import ExplorationProcess
from analysis import analyze_tainted_branch_data
from tracing import process_binary

logger = logging.getLogger(__name__)


def main(args):
    """Main function.
    """
    try:
        testcase_path = os.path.abspath(args[1])

        ea_start = int(args.setdefault(2, "0x0"), 16)
        ea_end = int(args.setdefault(3, "0x0"), 16)

        barf = BARF(testcase_path)
    except Exception as err:
        print(err)
        print("[-] Error opening file : %s" % testcase_path)

        sys.exit(1)

    if barf.testcase is None:
        print("No testcase specified. Execution impossible")

        sys.exit(-1)

    exploration = ExplorationProcess()

    input_counter = 0

    inputs = prepare_inputs(barf.testcase["args"] + barf.testcase["files"])
    branches_taint_data = process_binary(barf, inputs, ea_start, ea_end)
    analyze_tainted_branch_data(exploration, barf.code_analyzer, branches_taint_data, 0, testcase_path, input_counter)

    input_counter += 1

    while exploration.new_to_explore():
        _, input_file = exploration.next_to_explore()
        inputs = prepare_inputs(barf.testcase["args"] + [input_file])
        branches_taint_data = process_binary(barf, inputs, ea_start, ea_end)
        analyze_tainted_branch_data(exploration, barf.code_analyzer, branches_taint_data, 0, testcase_path, input_counter)
        input_counter += 1


if __name__ == "__main__":
    # NOTES:
    # 1. For now, it works only for programs compiled in 32 bits.
    # 2. For now, it only taints data from the 'read' function.

    if open("/proc/sys/kernel/randomize_va_space").read().strip() != "0":
        print("Address space layout randomization (ASLR) is enabled, disable it before continue")
        print("Hint: # echo 0 > /proc/sys/kernel/randomize_va_space")
        sys.exit(-1)

    main(dict(enumerate(sys.argv)))
