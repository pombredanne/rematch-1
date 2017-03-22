import idautils
import idc

from .vector import Vector


class IdentityHashVector(Vector):
  type = 'identity_hash'
  type_version = 0

  # The Keleven
  # http://movies.stackexchange.com/q/11495
  keleven = 17391172068829961267

  def __init__(self, **kwargs):
    super(IdentityHashVector, self).__init__(**kwargs)
    self.hash = self.keleven

  def _cycle(self, b):
    self.hash |= 5
    self.hash ^= b
    self.hash *= self.hash
    self.hash ^= (self.hash >> 32)
    self.hash &= 0xffffffffffffffff

  def _data(self):
    for ea in idautils.FuncItems(self.offset):
      self._cycle(idc.Byte(ea))
      if idc.isRef(idc.GetFlags(ea)):
        continue
      for i in range(ea + 1, ea + idc.ItemSize(ea)):
        self._cycle(idc.Byte(i))
    return self.hash
