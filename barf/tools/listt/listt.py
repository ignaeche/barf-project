#! /usr/bin/env python

import os
import sys
import copy
import cPickle

from barf.core.reil import ReilImmediateOperand
from barf.barf import BARF

def compute_summary(start_block, blocks, emulator, context_in):

  #emulator = barf.ir_emulator
  #emulator.taint("esp")
  #emulator.taint("ebp")

  #start = block.start_address
  #context_out = barf.emulate_full(context_in, 0x08048060, 0x0804806a + 0x2)
  print context_in
  block = blocks[start_block]
  instrs = []

  for ins in block.instrs:
    print str(ins.asm_instr)
    for rins in ins.ir_instrs:

      #context_in = {}
      #context_in["registers"] = {}
      #context_in["registers"]["esp"] = 0xdeadbeef
      #context_in["registers"]["ebp"] = 0xdeadbeef

      instrs.append(rins)
      #end = ins.address
      context_out = barf.emulate_reil(context_in, instrs)
      #start = end
      #context_in = context_out 

      if rins.mnemonic_str in ["ldm"]:
        addr = rins.operands[0]
        if isinstance(addr, ReilImmediateOperand):
          pass
        else:
          print str(addr), context_out["registers"][str(addr)] - 0xdeadbeef

      if rins.mnemonic_str in ["stm"]:
        addr = rins.operands[2]
        if isinstance(addr, ReilImmediateOperand):
          pass
        else:
          print str(addr), context_out["registers"][str(addr)] - 0xdeadbeef

  if block.taken_branch is not None:
    compute_summary(block.taken_branch, blocks, emulator, copy.copy(context_out))

  if block.not_taken_branch is not None:
    compute_summary(block.not_taken_branch, blocks, emulator, copy.copy(context_out))

  if block.direct_branch is not None:
    compute_summary(block.direct_branch, blocks, emulator, copy.copy(context_out))

  #assert(0)

        #print abs(context_out["registers"]["esp"] - 0xdeadbeef)
        #print abs(context_out["registers"]["ebp"] - 0xdeadbeef)
        #print str(context_out)
        #print map(lambda (x,y): (x,hex(y)), context_out.items())

  #if not(bb.taken_branch is None and bb.not_taken_branch is None and bb.direct_branch is None):
  # print bb.taken_branch, bb.not_taken_branch, bb.direct_branch
  # print "branches:",  
  # try:
  #   print hex(bb.taken_branch), hex(bb.not_taken_branch) 
  # except:
  #   print hex(bb.direct_branch)
  #assert(0)

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

    try: 
      pkl_file = open(output_dir + '.pkl', 'rb')
      cfg = cPickle.load(pkl_file)
    except IOError:
      cfg = barf.recover_cfg()
      pkl_file = open(output_dir + '.pkl', 'wb')
      cPickle.dump(cfg, pkl_file, -1) 

    print("[+] Computing some basic stats...")

    taint_sources = dict()
    taint_sources[0x8048a34] = 'getenv'
    taint_sources[0x8048b44] = 'fgetc'
    taint_sources[0x8048c24] = 'sscanf'


    taint_sinks = dict()
    taint_sinks[0x8048b54] = 'strcpy'
    taint_sinks[0x8048b04] = 'memcpy'
 
    blocks_by_address = cfg.basic_blocks_by_address
    blocks = set()
    
    calls = set()

    for i,bb in enumerate(cfg.basic_blocks):
      blocks.add(bb.address)
      for ins in bb.instrs:
        if "call" in str(ins.asm_instr) and  isinstance(ins.ir_instrs[-1].operands[-1], ReilImmediateOperand):

          #print str(ins.asm_instr), map(str,ins.ir_instrs)
          call_dst = ins.ir_instrs[-1].operands[-1].immediate >> 8
          calls.add(call_dst)

          if call_dst in taint_sources:
            print hex(bb.address), "is a taint source (", taint_sources[call_dst], ")"

          if call_dst in taint_sinks:
            print hex(bb.address), "is a taint sink (", taint_sinks[call_dst], ")"

    #print("Block:", map(hex,blocks))
    #print("Calls:", map(hex,calls))

    internal_calls = calls.intersection(blocks)
    print("Internal Calls", map(hex,internal_calls))

    for address in list(internal_calls)[:4]:
      print "[+] Computing summary for", hex(address)

      context_in = {}
 
      context_in["registers"] = {}
      context_in["registers"]["esp"] = 0xdeadbeef
      context_in["registers"]["ebp"] = 0xdeadbeef

      compute_summary(address, blocks_by_address, barf.ir_emulator, context_in)

    #assert(0)

    #if not os.path.exists(output_dir):
    #    os.mkdir(output_dir)

    #cfg.save(output_dir+'/', print_ir=False, format='dot')
    #cfg.save(output_dir+'/', print_ir=False, format='pdf')
