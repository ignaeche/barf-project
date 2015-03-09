
from ptrace.cpu_info import (CPU_POWERPC, CPU_INTEL, CPU_X86_64, CPU_I386, CPU_ARM)
from ptrace.ctypes_tools import bytes2word
from ptrace.debugger import ProcessExit, ProcessSignal, ProcessEvent

from barf.arch import (ARCH_X86, ARCH_X86_MODE_32, ARCH_X86_MODE_64)

from types import get_type
from specs import specs

class ProcessEnd(ProcessEvent):
  pass

class CallIntel32(ProcessEvent):

    def __init__(self, name, module):

        assert(name in specs)
        spec = specs[name]
        self.ret = str(spec[0])
        #fixme: void functions and non-returned values should be different!
        self.module = module
        self.name = str(name)
        self.param_types = list(spec[1:])
        self.param_ptypes = []
        self.param_values = []

    def __str__(self):
        return str(self.name)
    
    def detect_return_address(self, process):
        addr = process.getStackPointer()
        bs = process.readBytes(addr, 4)

        if CPU_X86_64:
            bs = bs + (4*'\00')

        self.return_address = bytes2word(bs)

    def detect_return_value(self, process):
      
        if CPU_I386:
            self.return_value = process.getreg("eax")
        elif CPU_X86_64:
            self.return_value = process.getreg("rax")
        else:
            assert(0)

    def _detect_parameter(self, offset):
        addr = self.process.getStackPointer()+offset
        bs = self.process.readBytes(addr, 4)

        if CPU_X86_64: 
            bs = bs + (4*'\00')

        return bytes2word(bs)

    def get_return_address(self):
        return self.return_address

    def get_return_value(self):
        return self.return_value

    def get_typed_parameters(self):
        return zip(self.param_values,self.param_ptypes)

    def detect_parameters(self, process):
        self.process = process
        offset = 4

        for ctype in self.param_types:

            value = self._detect_parameter(offset)
            ptype = get_type(ctype)
            self.param_values.append(value)
            self.param_ptypes.append(ptype)
            offset += ptype.getSize()

class Call(ProcessEvent):
    def __new__(self, name, module, (arch, arch_mode)):

        if CPU_INTEL and arch == ARCH_X86 and arch_mode == ARCH_X86_MODE_32:
            return CallIntel32(name, module)
        elif CPU_X86_64 and arch == ARCH_X86 and arch == ARCH_X86_MODE_64:
            raise NotImplemented("abc")
        else:
            print("[-] Error executing binary with '%s' architecture" % arch)
 
