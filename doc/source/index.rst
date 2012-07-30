.. mod_auth documentation master file, created by
   sphinx-quickstart on Wed Jul 25 15:43:15 2012.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to mod_auth's documentation!
====================================

Requirement
-----------
 - Python2.6+
 - M2Crypto library
 - Setuptools
 - pip


Installation
------------

To install mod_auth Library you can run this command from unix shell:

    >>> sudo pip install https://github.com/b3c/mod_auth/zipball/master


.. toctree::
   :maxdepth: 3
   
Mod_Auth
==================
 
.. automodule:: mod_auth.mod_auth

Simple use
==========
To start with mod_auth Library you can use Simple function to create and validate Ticket.
They based on mod_auth_tkt cookie authentication and work with minimum set of attribute , SECRET and USERID.
SECRET have to be shared with all server where you intend to use tickets system authetication.
Example of use:

  >>> from mod_auth import createSimpleTicket
  >>> from mod_auth import validateSimpleTicket
  >>> SECRET = 'b8fb7b6df0d64dd98b8ccd00577434d7'
  >>> userid = 'testUser'
  #Ticket creation
  >>> tkt = createSimpleTicket(SECRET,userid)
  >>> tkt
  >>> '1cfdad68a9f9b70227da2bbd99ca462e5011c7b7testUser!'
  #Ticket validation
  >>> validateSimpleTicket(tkt)
  >>> (u'testUser', (), u'', 1343342519)


.. automethod:: mod_auth.mod_auth.createSimpleTicket
.. automethod:: mod_auth.mod_auth.validateSimpleTicket

SignedTicket
============

.. autoclass:: mod_auth.mod_auth.SignedTicket

    .. automethod:: SignedTicket.validateTkt
    .. automethod:: SignedTicket.createTkt

Ticket
=======

.. autoclass:: mod_auth.mod_auth.Ticket

    .. automethod:: Ticket.validateTkt
    .. automethod:: Ticket.createTkt

Exception
=========

.. automodule:: mod_auth.exception
    :members:


LICENSE
=======
mod_auth is Copyright 2012 SuperComputer Solutions S.r.l (SCS)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.





Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


