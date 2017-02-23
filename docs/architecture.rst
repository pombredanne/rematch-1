Architecture
============

The rematch solution is divided into two main parts: a client and a server.
The server is in-charge of most of the heavy lifting, matching, and data
storage. The client is collecting :term:`Annotations <Annotation>` and
:term:`Vectors <Vector>`, applying annotations after matches are displayed to
the user and overall user interface.

Clients are designed to be replacable, however we only have an IDA client at
the moment.

Data Model
----------

