#!/usr/bin/env python

from barf import BARF

import os
import sys

if __name__ == "__main__":
    args = dict(enumerate(sys.argv))
    try:
        filename = os.path.abspath(args[1])
        ae_start = int(args.setdefault(2, "0x0"), 16)
        ae_end   = int(args.setdefault(3, "0x0"), 16)
        barf = BARF(filename)

    except Exception as err:
        print err
        print "[-] Error opening file : %s" % filename

        sys.exit(1)

    print("[+] Executing x86 to REIL...")

    for addr, asm_instr, reil_instrs in barf.execute(ae_start, ae_end):
        print("0x{0:08x} : {1}".format(addr, asm_instr))

        for reil_instr in reil_instrs:
            print("{0:14}{1}".format("", reil_instr))
