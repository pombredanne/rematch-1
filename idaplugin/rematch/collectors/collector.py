import json


try:
  strtypes = (str, unicode)  # noqa
except NameError:
  strtypes = (str,)


class Collector(object):
  def data(self):
    data = self._data()
    if not isinstance(data, strtypes):
      data = json.dumps(data)
    return data
