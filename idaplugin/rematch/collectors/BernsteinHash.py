from . import Vector 
from .. import exceptions
import idaapi


class BernsteinHashVec(Vector):

  # TODO refactor 
  # We have many hash functions which do the same
  # just create a class to iterate over it and implement digest
  def collect_insn(self,fn):
   lst = []
   fn_lst = []
   for bb in fn:
    for insn in bb.succs():
      start = bb.startEA
      end = bb.endEA
      while start < end:
        insn_len =  idaapi.decode_insn(start)
        indx = 0
        while indx < insn_len:
          lst.append(Byte(start +  indx))
          indx +=1
        start = NextHead(start)
      fn_lst.append(digest(lst))
      lst = []
    return fn_lst

  # this is the "modified better" version 
  # of the infamous bernstein hash 
  # http://www.eternallyconfuzzled.com/tuts/algorithms/jsw_tut_hashing.aspx
  # not safe at all for crytographic hashes, but one of the first
  # hashes by djb.
  # TODO XXX add more transformations 
  def digest(self,bytearr):
    r = 0
    for b in bytearr:
      r = 33 * r 
      r = r ^ b
    return r

  # ugly 
  def collect(self,ea):
    fn = idaapi.get_func(ea)
    if None == fn:
      raise exceptions.NoFunctionException()
    return collect_insn(fn)


