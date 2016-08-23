from . import HashVector
from .. import exceptions
import idaapi


class BernsteinHashVec(HashVector):
  def __init__(self):
    self.bb_lst = None
    self.type = 'BernsteinHash'
    self.type_version = 0

  '''
  this is the "modified better" version
  of the infamous bernstein hash
  http://www.eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx
  not safe at all for crytographic hashes, but one of the first
  hashes by djb.
  TODO XXX add more transformations
  '''
  def digest(self, bytearr):
    r = 0
    for b in bytearr:
      r = 33 * r
      r = r ^ b
    return r

  # ugly
  def collect(self, ea):
    fn = idaapi.get_func(ea)
    if fn is None:
      raise exceptions.NoFunctionException()
    return super(HashVector).collect_insn(fn)

  @property
  def data(self):
    if self.bb_lst is None:
      raise exceptions.NoFunctionException()
    return self.bb_lst
