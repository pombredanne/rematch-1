def test_plugin_creation(idapro_plugin_entry, idapro_app):
  del idapro_app

  plugin = idapro_plugin_entry()

  plugin.init()

  # TODO: validate return is of PLUGIN_* positive values

  plugin.run()

  plugin.term()


def test_action_creation(idapro_action_entry, idapro_app):
  del idapro_app

  action = idapro_action_entry(None)

  action.register()

  ctx = None

  action.update(ctx)

  action.activate(ctx)
