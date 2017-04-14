def test_plugin_creation(idapro_plugin_entry, ida_app):
  plugin = idapro_plugin_entry()

  plugin.init()

  # TODO: validate return is of PLUGIN_* positive values

  plugin.run()

  plugin.term()
