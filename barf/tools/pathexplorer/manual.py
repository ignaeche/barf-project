#!/usr/bin/env python
from __future__ import print_function

import logging
import os
import sys
import cPickle
import argparse

from barf.barf import BARF

logger = logging.getLogger(__name__)

def choose_branch(options):
    #
    # options: [(address, branch-name)]
    #
    keys = {x[1][0]: x for x in options}
    keys['q'] = (None, "quit")
    
    ask = "  "
    for i in keys:
        ask += "({0}) {1} ".format(i, keys[i][1])
    ask += ": "

    while True:
        key = raw_input(ask)
        if key in keys:
            return keys[key][0]

def manual_exploration(args):
    #
    # Open file
    #
    try:
        input_filename = os.path.abspath(args.path)
        output_dir = input_filename.split('/')[-1] + "_cfg"
        barf = BARF(input_filename)

        ea_start = args.start
        ea_end = args.end
    except Exception as err:
        print(err)
        print("[-] Error opening file : %s" % input_filename)
        sys.exit(1)

    #for addr, asm_instr, reil_instrs in barf.translate(ea_start, ea_end):
    #    print("0x{addr:08x} {instr}".format(addr=addr, instr=asm_instr))

    #
    # Recover CFG
    #
    print("[+] Recovering program CFG...")

    try: 
        pkl_file = open(output_dir + '.pkl', 'rb')
        cfg = cPickle.load(pkl_file)
    except IOError:
        cfg = barf.recover_cfg(ea_start=ea_start, ea_end=ea_end)
        pkl_file = open(output_dir + '.pkl', 'wb')
        cPickle.dump(cfg, pkl_file, -1)

    blocks_by_address = dict()

    #
    # Find first block and construct dict with blocks by addr.
    #
    for bb in cfg.basic_blocks:
        print("  [+] Basic Block with address 0x%X" % bb.address)
        blocks_by_address[bb.address] = bb
        if bb.address == ea_start:
            first_block = bb
            print("    [+] First block found")
    
    try:
        current_block = first_block
    except Exception:
        print("[-] First block not found")
        sys.exit(1)

    #
    # Manual exploration
    #
    while current_block is not None:
        print("{0}\n{0}".format("~" * 80))
        print("[+] Basic block with address 0x%X" % current_block.address)

        for _, ins in enumerate(current_block.instrs):
            #print("    [+] Instruction %d" % i)
            print("    [+] %s" % ins.asm_instr)

            if args.reil:
                #print("      [+] REIL translation")
                for reil_ins in ins.ir_instrs:
                    print("      [+] %s" % reil_ins)
    
        branches = current_block.branches
        if branches != []:
            print("  [+] Branches: {0}".format(map(lambda x : x[1], branches)))
            next_address = choose_branch(branches)
            if next_address is not None:
                current_block = blocks_by_address[next_address]
            else:
                current_block = None
        else:
            print("[+] No more branches")
            current_block = None

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser()

    parser.add_argument('path')
    parser.add_argument('--reil', action='store_true')

    hex_int = lambda x : int(x, 16)
    parser.add_argument('--start', type=hex_int, default='0x0')
    parser.add_argument('--end', type=hex_int, default='0x0')

    args = parser.parse_args()

    manual_exploration(args)
