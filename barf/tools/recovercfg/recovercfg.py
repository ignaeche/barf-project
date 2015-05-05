#! /usr/bin/env python

import os
import sys

from barf.barf import BARF

if __name__ == "__main__":
    #
    # Open file
    #
    try:
        input_filename = os.path.abspath(sys.argv[1])
        output_dir = input_filename.split('/')[-1] + "_cfg"
        barf = BARF(input_filename)
    except Exception as err:
        print err

        print "[-] Error opening file : %s" % input_filename

        sys.exit(1)

    #
    # Recover CFG
    #
    print("[+] Recovering program CFG...")

    cfg = barf.recover_cfg()
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    cfg.save(output_dir+'/', print_ir=False, format='dot')
    cfg.save(output_dir+'/', print_ir=False, format='pdf')
