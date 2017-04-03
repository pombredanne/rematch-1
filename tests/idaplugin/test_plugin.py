from idaplugin import plugin_rematch


def test_plugin_creation():
  from PyQt5 import QtWidgets
  qapp = QtWidgets.QApplication([])

  plugin = plugin_rematch.PLUGIN_ENTRY()

  plugin.init()

  # TODO: validate return is of PLUGIN_* positive values

  plugin.run()

  plugin.term()
