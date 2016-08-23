from . import HashVector
from .. import exceptions
import idaapi


# we only do 64b-len hashes, not 32b
# TODO XXX create a native function to do this hash
class FnvHashVector(HashVector):
  FNV_P = 0x100000001b3
  FNV_OFF_BASE = 0xcbf29ce484222325
  BITNESS = 2**64

  def __init__(self):
    self.type = 'FnvHash'
    self.type_version = 0
    self.bb_lst = None

  def data(self):
    if self.bb_lst is None:
      raise exceptions.NoFunctionException()
    return self.bb_lst

  def digest(self, bytearr):
    h = FnvHashVector.FNV_OFF_BASE
    for b in bytearr:
      h = h ^ b
      h = (h * FnvHashVector.FNV_P) % FnvHashVector.BITNESS
    return h

  def collect(self, ea):
    fn = idaapi.get_func(ea)
    if fn is None:
      raise exceptions.NoFunctionException()
    return super(HashVector).collect_insn(fn)
