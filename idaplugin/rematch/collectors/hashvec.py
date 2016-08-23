from . import Vector


class HashVector(Vector):
  # TODO refactor
  # We have many hash functions which do the same
  # just create a class to iterate over it and implement digest
  def collect_insn(self, fn):
   lst = []
   self.bb_lst = []
   for bb in fn:
    for insn in bb.succs():
      start = bb.startEA
      end = bb.endEA
      while start < end:
        insn_len = idaapi.decode_insn(start)
        indx = 0
        while indx < insn_len:
          lst.append(Byte(start + indx))
          indx += 1
        start = NextHead(start)
      self.bb_lst.append(digest(lst))
      lst = []
    return self.bb_lst
