Installation
============

The rematch project is composed of two parts: a server and an IDA plugin client.

While installing the plugin is exteremly easy, installing the server tends to
be a little more difficult. Luckily, it's only done once per organisation.

Installing the Rematch Server
-----------------------------

Installing a rematch server is only required once for a group of rematch users.
Once an admin user is created, additional users can be managend through the
admin console.

.. warning:: Since permissions are not currently enforced, it is advised that
  confidential data will be kept on servers only accessible to those with
  permission to access said data. See Privacy section for more details.

Installing the Rematch IDA Plugin
---------------------------------

Installing IDA plugins is done by placing the plugin source inside IDA's
plugins directory (location is based on operating system). To make plugin
installation as simple as possibe, the rematch plugin has no dependecies.

Once installed the plugin automatically updates itself (as long as it's
configured to), so installing the plugin is a one-time process.

Installing the plugin using pip
+++++++++++++++++++++++++++++++

If pip is installed for IDA's version of python, using it is simplest
installation method.

.. note:: By default, pip is not installed for Windows installation of IDA, but
   is more commonly found in Mac and Linux installations.

To install using IDA's pip, simply run the following pip command:

.. code-block:: console

   $ pip install rematch-idaplugin

.. warning:: Make sure you're installing the plugin using a version of pip
   inside IDA's copy of python.

If pip is not installed for IDA's version of python, it is still possible to
install the plugin with another copy of pip using pip's `--target` flag. To do
this run the following pip command line with any instance of pip:

.. code-block:: console

   $ pip install rematch-idaplugin --target="<Path to IDA's plugins directory>"

.. note:: IDA's plugins directory is located inside IDA's installation
   directory. For example if IDA is installed at:

   `C:\Program Files (x86)\IDA 6.9`

   Then the plugins directory will be:

   `C:\Program Files (x86)\IDA 6.9\plugins`

   and the executed command line should be:

   .. code-block:: console

      $ pip install rematch-idaplugin
          --target="C:\Program Files (x86)\IDA 6.9\plugins"

Installing the plugin manually
++++++++++++++++++++++++++++++

If you don't have pip, or prefer not to use it, you can still manually install
the plugin by simply extacting the contents of the `idaplugin directory
<https://github.com/nirizr/rematch/tree/master/idaplugin>`_ in the repository's
root, to IDA's plugins directory.

Simply download the package from `PyPI
<https://pypi.python.org/pypi/rematch-idaplugin>`_ or `Github
<https://github.com/nirizr/rematch>`_ and extract the idaplugin directory into
IDA's plugins directory.
