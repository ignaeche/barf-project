#! /usr/bin/env python

import os
import sys

from barf.barf import BARF

if __name__ == "__main__":
    #
    # Open file
    #
    try:
        filename = os.path.abspath("../samples/toy/taint2")
        barf = BARF(filename)
    except Exception, err:
        print "[-] Error opening file : %s" % filename

        sys.exit(1)

    #
    # REIL emulation
    #
    emulator = barf.ir_emulator

    emulator.taint("ebx")
    emulator.taint("ebx")

    context_in = {}

    context_in["registers"] = {}
    context_in["registers"]["ebx"] = 0xa
    context_in["registers"]["esp"] = 0x00000000

    emulator._mem.taint(0x00000004, 32)

    # context_out = barf.emulate_full(context_in, 0x08048060, 0x08048072 + 0x2)
    context_out = barf.emulate_full(context_in, 0x08048060, 0x0804806b + 0x2)

    print "%s : %s" % ("eax", hex(context_out['registers']["eax"]))

    # assert(context_out['registers']["eax"] == 0xa)

    print emulator.is_tainted("eax")
