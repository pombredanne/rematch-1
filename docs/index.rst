.. Rematch documentation master file, created by
   sphinx-quickstart on Mon Jan 30 23:39:51 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Rematch
=======

Rematch, a simple binary diffing utility that just works.

.. note::
  At least, we hope it will be. Rematch is still a work in progress and is not
  fully functional at the moment. We're currently working on bringing up basic
  functionality. Check us out again soon, or watch for updates!

Rematch is intended to be used by reverse engineers for revealing and
identifying previously reverse engineered similar functions, and then
migrating documentation and annotations to current IDB. Rematch does that by
locally collecting and uploading data about functions in your IDB. Rematch
uploads information to a web service (which you're supposed to set up as well),
that upon request, is able to match your functions against all (or part) of
existing database of previously uploaded functions and provide matches.

A secondary goal of rematch (which is not currently pursued) is to allow
synchronization between multiple reverse engineers working on the same file.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   architecture
   installation
   usage
   engines
   glossary

Goal of Rematch
---------------

The goal of Rematch is to act as a maintained, extendable, open source tool for
advanced assembly function-level binary comparison and matching. Hopefully,
this will be a completely open source and free (as in speech) community-driven
tool.

We've noticed that although there are more than a handful of existing binary
matching tools, there's no one tool that provides all of the following:

1. Open source and community driven.
2. Supports advanced matching algorithms (ML included ™).
3. Fully integrated into IDA.
4. Allows managing multiple projects in a single location.
5. Enables out of the box one vs. many matches.
6. Actively maintained.

Contribute and Get Support
--------------------------

- Source Code: https://github.com/nirizr/rematch
- Issue Tracker: https://github.com/nirizr/rematch/issues
- IRC channel: `ircs://freenode/#rematch <ircs://freenode/#rematch>`_ (or
  `insecure <irc:freenode/#rematch>`_)
- Gitter Chat: https://gitter.im/rematch/rematch

License
-------

The project is licensed under the GNU-GPL v3 license.
