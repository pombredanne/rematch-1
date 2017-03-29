from .. import user, log, netnode, utils

import idaapi
import idc


class Action():
  reject_handler = None
  finish_handler = None
  submit_handler = None
  response_handler = None
  exception_handler = None

  def __init__(self, ui_class):
    self.ui_class = ui_class
    self.ui = None

  def __repr__(self):
    return "<Action: {}>".format(self.ui_class)

  def running(self):
    return self.ui is not None


class IDAAction(idaapi.action_handler_t, Action):
  """Actions are objects registered to IDA's interface and added to the
  rematch menu and toolbar"""

  def __init__(self, *args, **kwargs):
    super(IDAAction, self).__init__(*args, **kwargs)
    self._icon = None

  def __repr__(self):
    return "<Action: {}, {}>".format(self.get_id(), self.ui_class)

  def __del__(self):
    super(IDAAction, self).__del__()
    if self._icon:
      idaapi.free_custom_icon(self._icon)

  def get_name(self):
    return self.name

  def get_id(self):
    return self.get_name().replace('&', '').replace(' ', '_').lower()

  def get_text(self):
    if hasattr(self, 'text'):
      return self.text
    else:
      return self.get_name().replace("&", "")

  def get_shortcut(self):
    if hasattr(self, 'shortcut'):
      return self.shortcut
    else:
      return ""

  def get_tooltip(self):
    if hasattr(self, 'tooltip'):
      return self.tooltip
    else:
      return self.get_text()

  def get_icon(self):
    if not self._icon:
      image_path = utils.getPluginPath('images', self.get_id() + ".png")
      self._icon = idaapi.py_load_custom_icon_fn(image_path)
    return self._icon

  def get_desc(self):
    return idaapi.action_desc_t(
      self.get_id(),
      self.get_text(),
      self,
      self.get_shortcut(),
      self.get_tooltip(),
      self.get_icon())

  def get_action_group(self):
    if hasattr(self, 'group'):
      return self.group
    else:
      return ""

  def get_action_path(self):
    t = ["Rematch"]

    if self.get_action_group():
      t.append(self.get_action_group())

    t.append(self.get_name())

    return '/'.join(t)

  def register(self):
    r = idaapi.register_action(self.get_desc())
    if not r:
      log('actions').warn("failed registering %s: %s", self, r)
      return
    idaapi.attach_action_to_menu(
        self.get_action_path(),
        self.get_id(),
        idaapi.SETMENU_APP)
    r = idaapi.attach_action_to_toolbar(
        "AnalysisToolBar",
        self.get_id())
    if not r:
      log('actions').warn("registration of %s failed: %s", self, r)

  def update(self, ctx):
    return idaapi.AST_ENABLE if self.enabled(ctx) else idaapi.AST_DISABLE

  def activate(self, ctx):
    del ctx
    if self.running():
      return

    if callable(self.ui_class):
      self.ui = self.ui_class(reject_handler=self.reject_handler,
                              submit_handler=self.submit_handler,
                              response_handler=self.response_handler,
                              exception_handler=self.exception_handler)
      if self.finish_handler:
        self.ui.finished.connect(self.finish_handler)
      self.ui.finished.connect(self.close_dialog)
      self.ui.finished.connect(self.force_update)
      self.ui.show()
    else:
      log('actions').warn("%s: no activation", self.__class__)

  def close_dialog(self):
    del self.ui
    self.ui = None

  @staticmethod
  def force_update():
    """Forcefuly requests IDA kernel to update all widgets and views. Useful
    for when delayed actions modify the program and/or plugin state without
    IDA's awareness"""
    iwid_all = 0xFFFFFFFF
    idaapi.request_refresh(iwid_all)


class IdbAction(IDAAction):
  """This action is only available when an idb file is loaded"""
  @staticmethod
  def enabled(ctx):
    del ctx
    return bool(idc.GetIdbPath())


class UnauthAction(IDAAction):
  """This action is only available when a user is logged off"""
  @staticmethod
  def enabled(ctx):
    del ctx
    return not bool(user['is_authenticated'])


class AuthAction(IDAAction):
  """This action is only available when a user is logged in"""
  @staticmethod
  def enabled(ctx):
    del ctx
    return bool(user['is_authenticated'])


class AuthIdbAction(AuthAction, IdbAction):
  """This action is only available when an idb file is loaded and a user is
  logged in"""
  @staticmethod
  def enabled(ctx):
    return AuthAction.enabled(ctx) and IdbAction.enabled(ctx)


class BoundFileAction(AuthIdbAction):
  """This action is only available when a file bound to the remote server is
  loaded"""
  @staticmethod
  def enabled(ctx):
    if not AuthIdbAction.enabled(ctx):
      return False

    return bool(netnode.bound_file_id)


class UnboundFileAction(AuthIdbAction):
  """This action is only available when no file is bound to the remote
  server"""
  @staticmethod
  def enabled(ctx):
    if not AuthIdbAction.enabled(ctx):
      return False

    return not bool(netnode.bound_file_id)
