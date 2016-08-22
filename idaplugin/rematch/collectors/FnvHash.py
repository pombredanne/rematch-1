from . import Vector 
from .. import exceptions
import idaapi

# we only do 64b-len hashes, not 32b
# TODO XXX create a native function to do this hash
class FnvHashVector(Vector):

  FNV_P = 0x100000001b3
  FNV_OFF_BASE = 0xcbf29ce484222325
  BITNESS = 2**64

  def __init__(self):
    self.type = 'FnvHash'
    self.type_version = 0
    self.bb_lst = None

  def data(self):
    if self.bb_lst == None:
      raise exceptions.NoFunctionException()
    return self.bb_lst

  # TODO XXX multiplex.
  # Move from Byte to Dword.
  #  For every basic block 
  # calculate FNV Hash.
  # then add it to a global lst
  def collect_insn(self,fn):
    lst = []
    self.bb_lst = []
    for basicblock in fn:
      for insn in basicblock.succs():
        bb_start = insn.startEA
        bb_end = insn.endEA
        while bb_start < bb_end:
          insn_len = idaapi.decode_insn(bb_start)
          indx = 0
          while indx < insn_len:
            lst.append(Byte(bb_start + indx))
            indx +=1
          bb_start = NextHead(bb_start)
        self.bb_lst.append(digest(lst))
        lst = [] 
    return self.bb_lst

  def digest(self,bytearr): 
    h = FnvHash.FNV_OFF_BASE
    for b in bytearr:
      h = h ^ b
      h = (h * FnvHash.FNV_P) % FnvHash.BITNESS
    return h

  # ugly 
  def collect(self,ea): 
    fn = idaapi.get_func(ea)
    if None == fn:
      raise exceptions.NoFunctionException()
    return collect_insn(fn)

