#!/usr/bin/python2

import os
import argparse
import sys
import csv

from barf.core.dbg.testcase import write_testcase

if __name__ == "__main__":

    # Arguments
    parser = argparse.ArgumentParser(description='')
    parser.add_argument("name", help="", type=str, default=None)
    parser.add_argument("cmd", help="", type=str, default=None)
    parser.add_argument("--copy", help="", action='store_true', default=False)

    parser.add_argument("outdir", help="Output directory to write testcases", type=str, default=None)

    options = parser.parse_args()
    name = options.name
    cmd = options.cmd
    copy = options.copy
    out_dir= options.outdir

    try:
      os.makedirs(out_dir)
    except:
      pass

    os.chdir(out_dir)
    args = filter(lambda x: x is not '', cmd.split(" "))
    write_testcase(name,args[0],args[1:], copy)

