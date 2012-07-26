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

    >>> sudo pip install https://github.com/asaglimbeni/mod_auth/zipball/master


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
mod_auth is copyright SuperComputer Solutions S.r.l. (SCS_)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the name of the author nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


