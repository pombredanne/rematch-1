Glossary
========

.. glossary::

   Annotation
     A piece of information describing an :term:`Entity` in more detail, often
     created by the user while reverse engineering as part of the reverse
     engineering process. Annotations help the reverse engineer and therefore
     there's an advantage in applying annotations to matched :term:`Entities
     <Entity>`.
 
   Entity
     When used throughtout these docs, an Entity generally means a matchable
     object inside a binary file, or it's representation in any rematch
     component.

     The following are currently entities:

     #. A function defined within a binary executable.
     #. A function imported into a binary file from another binary.
     #. A stream of initialised data or structure.
     #. A stream of uninitialised data or structure.
  
   Vector
      Raw data used to describe an :term:`Entity` in a way that facilitates and
      enables matching. Those are also occasionally called features in data-
      science and machine learning circles.
 
   Matcher
      Matchers implement the logic of matching :term:`Entities <Entity>`
      together using thier :term:`Vectors <Vector>`.
