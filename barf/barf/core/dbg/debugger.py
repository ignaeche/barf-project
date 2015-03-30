# Copyright (c) 2014, Fundacion Dr. Manuel Sadosky
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.

# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Generic Debugger Interface.
"""
from signal import SIGTRAP
from time import sleep

from barf.core.bi import LibC
from run import createChild
from event import *
from ptrace.debugger import PtraceDebugger
from ptrace.error import PtraceError
from ptrace.ctypes_tools import (truncateWord, formatWordHex, formatAddress,
                                 formatAddressRange, word2bytes)

class Debugger(PtraceDebugger):
    pass

class ProcessControl(object):
    def __init__(self):
        self.dbg = Debugger()
        self.process = None
        self.last_signal = []

        self.last_event = None
        self.last_call_ip = None
        self.last_return_ip = None

    def start_process(self, binary, args, ea_start, ea_end, hooked_functions = []):
        self.binary = binary

        self.arch = self.binary.architecture
        self.arch_mode = self.binary.architecture_mode

        self.filename = binary.filename
        self.args = list(args)

        if ea_start == 0x0:
            ea_start = self.binary.start_address

        self.ea_start = ea_start
        self.ea_end   = ea_end
        self.hooked_functions = dict()

        pid = createChild([self.filename]+self.args, 0)
        self.process = self.dbg.addProcess(pid, is_attached=1)

        self.breakpoint(ea_start)
        self.cont()

        self.mm = self.process.readMappings()
        self.libs_start = dict()

        for m in self.mm:
            if m.pathname not in [None, "[vsyscall]", "[vdso]"] and 'x' in m.permissions:
                self.libs_start[m.pathname] = m.start

        lib_filename = LibC.path
        lib_symbols = LibC.symbols

        for func in hooked_functions:
                if func in lib_symbols:
                    addr = self.libs_start[lib_filename] + lib_symbols[func]
                    self.breakpoint(addr)
                    self.hooked_functions[addr] = func, lib_filename
                    print "[+] Hooking",func,"at",hex(addr), lib_filename#, self.libs_start[lib_filename], self.libs_start[lib_filename]

        return self.process

    def wait_event(self):
        event = self.dbg.waitProcessEvent()

        if not isinstance(event, ProcessExit):
            if self.process.getInstrPointer() == self.ea_end:
                return ProcessEnd(self.process, "Last instruction reached")

        return event

    def _continue_process(self, process, signum=None):
        if not signum and process in self.last_signal:
            signum = self.last_signal[process]

        if signum:
            error("Send %s to %s" % (signalName(signum), process))
            process.cont(signum)
            try:
                del self.last_signal[process]
            except KeyError:
                pass
        else:
            process.cont()

    def cont(self, signum=None):
        event = None
        process = self.process
        process.syscall_state.clear()
        if process == self.process:
            self._continue_process(process, signum)
        else:
            self._continueProcess(process)

        #print process.getInstrPointer()

        signal = self.dbg.waitSignals()
        if signal.signum == SIGTRAP:
            ip = process.getInstrPointer()
            ip = ip - 1

            if ip in self.hooked_functions:
                print "ENTERING HOOK FUNCTION"
                call_ip = ip

                # remove call breakpoint
                breakpoint = self.process.findBreakpoint(call_ip)
                breakpoint.desinstall(set_ip=True)

                # extract argument
                name, module = self.hooked_functions[ip]
                event = Call(name, module, (self.arch, self.arch_mode))
                event.detect_parameters(self.process)
                event.detect_return_address(self.process)

                #print event.name, map(hex,event.param_values)

                return_address = event.get_return_address()
                #print "adding:", hex(return_address)

                # hook return address
                self.breakpoint(return_address)

                # continue until return
                self.process.cont()
                self.dbg.waitProcessEvent()

                # extract return value
                event.detect_return_value(self.process)

                ip = process.getInstrPointer()
                ip = ip - 1

                return_ip = ip

                #print "removing:", hex(return_ip)
                assert(return_address == return_ip)

                # remove return breakpoint
                breakpoint = self.process.findBreakpoint(return_ip)
                breakpoint.desinstall(set_ip=True)

                # reinstall call breakpoint
                self.breakpoint(call_ip)
            else:
                breakpoint = self.process.findBreakpoint(ip)
                breakpoint.desinstall(set_ip=True)

        return event

    def single_step(self,signum=None):
        event = None
        process = self.process
        process.syscall_state.clear()

        process.singleStep()

        event = self.wait_event()

        if isinstance(event, ProcessExit) or isinstance(event, ProcessEnd):
            return event

        ip = process.getInstrPointer()
        ip = ip - 1

        if ip in self.hooked_functions:
                print "ENTERING HOOK FUNCTION"
                self.last_call_ip = ip

                # remove call breakpoint
                breakpoint = self.process.findBreakpoint(self.last_call_ip)
                breakpoint.desinstall(set_ip=True)

                # extract argument
                name, module = self.hooked_functions[ip]
                event = Call(name, module, (self.arch, self.arch_mode))
                event.detect_parameters(self.process)
                event.detect_return_address(self.process)

                self.last_event = event

                #print event.name, map(hex,event.param_values)

                self.last_return_ip = event.get_return_address()
                #print "adding:", hex(return_address)

                # hook return address
                self.breakpoint(self.last_return_ip)

                return None

                # continue until return
                #self.process.cont()
                #self.dbg.waitProcessEvent()

        elif ip == self.last_return_ip:
                # extract return value
                print self.last_return_ip, self.last_event, hex(ip)
                #print hex(ip)

                assert(self.last_event is not None)
                assert(self.last_return_ip is not None)

                self.last_event.detect_return_value(self.process)

                #ip = process.getInstrPointer()
                #ip = ip - 1

                return_ip = ip

                #print "removing:", hex(return_ip)
                assert(self.last_return_ip == return_ip)

                # remove return breakpoint
                breakpoint = self.process.findBreakpoint(return_ip)
                breakpoint.desinstall(set_ip=True)

                # reinstall call breakpoint
                self.breakpoint(self.last_call_ip)

                self.last_call_ip = None
                self.last_return_ip = None
                self.last_event = None

                return event

    def breakpoint(self, address):

        process = self.process
        # Create breakpoint
        size = None
        try:
            bp = process.createBreakpoint(address, size)
        except PtraceError, err:
            return "Unable to set breakpoint at %s: %s" % (
                formatAddress(address), err)
        #error("New breakpoint: %s" % bp)
        return bp

    def get_context(self, registers, mapper):
        context = {}
        #print "mapper:",mapper
        for reg in registers:
            # FIXME: Temporary ugly hack...
            if reg == 'rflags':
                continue

            #print "reg",reg
            if reg in mapper:
                base, offset = mapper[reg]
            else:
                base, offset = reg, 0

            value = self.process.getreg(base)
            # print "base-value-offset", base, value, offset
            context[reg] = self._extract_value(value, offset, 32)


        value = self.process.getreg('eflags')

        context['eflags'] = self._extract_value(value, 0, 32)

        return context

    def _extract_value(self, main_value, offset, size):
        return (main_value >> offset) & 2**size-1

    def _insert_value(self, main_value, value_to_insert, offset, size):
        main_value &= ~((2**size-1) << offset)
        main_value |= (value_to_insert & 2**size-1) << offset

        return main_value
