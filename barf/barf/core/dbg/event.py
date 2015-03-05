
from ptrace.ctypes_tools import bytes2word
from ptrace.debugger import ProcessExit, ProcessSignal, ProcessEvent
from types import get_type
from specs import specs

class ProcessEnd(ProcessEvent):
  pass

class Call(ProcessEvent):

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
    addr = process.getStackPointer()#getreg("esp")
    bs = process.readBytes(addr, 4)
    bs = bs+(8-len(bs))*'\00'
    self.return_address = bytes2word(bs)
    print hex(self.return_address)

  def detect_return_value(self, process):
    try:
        self.return_value = process.getreg("rax")
    except _:
        self.return_value = process.getreg("eax")

  def _detect_parameter(self, offset):
    addr = self.process.getStackPointer()+offset#getreg("esp")+offset
    bs = self.process.readBytes(addr, 4)
    bs = bs+(8-len(bs))*'\00'
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


