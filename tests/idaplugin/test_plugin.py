from idaplugin import plugin_rematch

import threading


def test_plugin_creation():
  from PyQt5 import QtWidgets
  qapp = QtWidgets.QApplication([])
  qmainwin = QtWidgets.QMainWindow()
  qmdiarea = QtWidgets.QMdiArea()
  qmainwin.setCentralWidget(qmdiarea)
  qmenu = QtWidgets.QMenu()
  qmainwin.setMenuWidget(qmenu)
  t = threading.Thread(target=qapp.exec_)
  t.start()

  plugin = plugin_rematch.PLUGIN_ENTRY()

  plugin.init()

  # TODO: validate return is of PLUGIN_* positive values

  plugin.run()

  plugin.term()
