#!/usr/bin/env python
from __future__ import print_function

import logging
import os
import sys
import argparse

from barf import BARF

from barf.core.dbg.testcase import prepare_inputs

from exploration import ExplorationProcess
from analysis import analyze_trace
from tracing import trace_program

logger = logging.getLogger(__name__)

def print_input_file_content(inputs):
    if len(inputs) > 0:
        with open(inputs[0], "r") as f:
            content = "".join(f.readlines())

        print("[+] Input file content: {}".format(content))

def main(args):
    """Main function.
    """
    try:
        testcase_path = os.path.abspath(args.path)

        ea_start = args.start
        ea_end = args.end

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

    ##
    # print([str(i) for i in inputs])
    print_input_file_content(inputs)
    ##

    trace_data = trace_program(barf, inputs, ea_start, ea_end)
    analyze_trace(exploration, barf.code_analyzer, trace_data, testcase_path, input_counter)

    input_counter += 1

    while exploration.new_to_explore():
        _, input_file = exploration.next_to_explore()
        inputs = prepare_inputs(barf.testcase["args"] + [input_file])

        ##
        # print([str(i) for i in inputs])
        print_input_file_content(inputs)
        ##

        trace_data = trace_program(barf, inputs, ea_start, ea_end)
        analyze_trace(exploration, barf.code_analyzer, trace_data, testcase_path, input_counter)
        input_counter += 1


if __name__ == "__main__":
    # NOTES:
    # 1. For now, it works only for programs compiled in 32 bits.
    # 2. For now, it only taints data from the 'read' function.

    if open("/proc/sys/kernel/randomize_va_space").read().strip() != "0":
        print("Address space layout randomization (ASLR) is enabled, disable it before continue")
        print("Hint: # echo 0 > /proc/sys/kernel/randomize_va_space")
        sys.exit(-1)

    # Argument parsing
    parser = argparse.ArgumentParser()

    parser.add_argument('path')
    parser.add_argument('--manual', action='store_true')

    hex_int = lambda x : int(x, 16)
    parser.add_argument('--start', type=hex_int, default='0x0')
    parser.add_argument('--end', type=hex_int, default='0x0')

    args = parser.parse_args()

    if args.manual:
        # Manual exploration
        print("Manual exploration")
    else:
        main(args)
