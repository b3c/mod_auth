
Welcome to mod_auth's documentation!
************************************


Requirement
===========

   * Python2.6+

   * M2Crypto library

   * Setuptools

   * pip


Installation
============

To install mod_auth Library you can run this command from unix shell:

>>> sudo pip install https://github.com/asaglimbeni/mod_auth/zipball/master


Mod_Auth
********

This module implements the session cookie format from mod_auth_tkt and
mod_auth_pubtkt. In this documentation show you how to use and
integrate mod_auth library into your project.

Contributors:

Before start I want say a BIG TANKS to plone.session team for
tkauth.py module. It help us to start with this library:

   plone-session: https://github.com/plone/plone.session/blob/master/p
   lone/session/tktauth.py

And to Andrey Plotnikov for a easy implementation fo mod_auth_pubtkt

   auth_pubtkt: https://github.com/AndreyPlotnikov/auth_pubtkt


mod_auth_tkt style cookie authentication
========================================

Mod_auth library implements the session cookie format from
mod_auth_tkt, the class used is Ticket. Now "createTicket" and
"validateTicket" functions use the MD5 based double hashing scheme in
the original mod_auth_tkt.


Configuration
-------------

In mod_auth_tkt the protocol depends on a secret string shared between
servers. From time to time this string should be changed, so store it
in a configuration file.

>>> SECRET = 'b8fb7b6df0d64dd98b8ccd00577434d7'

The tickets are only valid for a limited time. Here we will use 24
hours

>>> DEFAULT_TIMEOUT = 24*60*60


Ticket creation
---------------

The minimal set of attributes to create a ticket are composed only
from a userid:

>>> userid = 'testUser'

First stemp is to init Ticket object:

>>> from mod_auth import Ticket
>>> mod_auth_Ticket = Ticket(SECRET)

So, set the validuntil that the user will log out.

>>> validuntil = int(time.time())+ (24*60*60)

We will create a mod_auth_tkt compatible ticket. In the simplest case
no extra data is supplied.

>>> ticket = mod_auth_Ticket.createTkt(userid,validuntil=validuntil)
>>>'b054eeab313d4b75e10f4fd4ddb36ecf50115dcctestUser!'

The cookie itself should be base64 encoded. We will use the built-in
Cookie module here, your web framework may supply it's own mechanism.

>>> import Cookie, binascii
>>> cookie = Cookie.SimpleCookie()
>>> cookie['auth_tkt'] = binascii.b2a_base64(ticket).strip()
>>> print cookie
Set-Cookie: auth_tkt=YjA1NGVlYWIzMTNkNGI3NWUxMGY0ZmQ0ZGRiMzZlY2Y1MDExNWRjY3Rlc3RVc2VyIQ==


Ticket validation
-----------------

First the ticket has to be read from the cookie and unencoded:

>>> ticket = binascii.a2b_base64(cookie['auth_tkt'].value)
>>> ticket
'b054eeab313d4b75e10f4fd4ddb36ecf50115dcctestUser!'

The server that invoke validateTkt and open a session cookie need of
the SECRET to validate the digest into ticket.

Init the Ticket object:

>>> from mod_auth import Ticket
>>> mod_auth_Ticket = Ticket(SECRET)

next step is to validate:

>>> mod_auth_Ticket.validateTkt(ticket)
>>> (u'testUser', (), u'', 1343315404)

If the ticket is valid and not expired , validateTkt return all
information about logged user else raise an Exception (see function
documentation for detail)


Tokens and user data
--------------------

The format allows for optional user data and tokens. For detail you
can see the test.py into mod_auh module, where there are some use test
of this class. Here an example:

>>> Secret = str(uuid.uuid4().hex)
>>> # Init SignedTicket object
>>> simpleTicket = Ticket(Secret)

>>> #USER DATA

>>> userid = 'TestUser'
>>> tokens = ('role1', 'role2')
>>> userdata = ('testuser@mail.com','Italy','Bologna')
>>> cip = '127.0.0.1'
>>> # ticket is valdi until 24 from now
>>> validuntil = int(time.time())+ (24*60*60)

>>> #END USERDATA

>>> ticket = simpleTicket.createTkt(userid,tokens,userdata,cip,validuntil)


Mod_auth_pubtkt style cookie authentication
===========================================

mod_auth_pubtkt is a module that authenticates a user based on a
cookie with a ticket that has been issued by a central login server
and digitally signed using either RSA or DSA. This means that only the
trusted login server has the private key required to generate tickets,
while web servers only need the corresponding public key to verify
them.

In mod_auth module is implemented  by SignedTicket class.


Configuration
-------------

BE CAREFUL!For your safety, please, if you use this module in your
project, generate new keys (DSA or RSA) , to do that see the section
below:

From your unix shell. DSA:

   openssl dsaparam -out dsaparam.pem 2048

   openssl gendsa -out privDSAkey.pem dsaparam.pem

   openssl dsa -in privDSAkey.pem -out pubDSAkey.pem -pubout

   The dsaparam.pem file is not needed anymore after key generation
   and can safely be deleted.

RSA:

   openssl genDSArsa -out privkey.pem 2048

   openssl rsa -in privDSAkey.pem -out pubkey.pem -pubout


Ticket creation
---------------

Like into Ticket class , the minimal set of attributes to create a
ticket are composed only by a userid:

>>> userid = 'testUser'

First stemp is to init SignedTicket object with your keys:

>>> from mod_auth import SignedTicket
>>> mod_auth_pubTicket = Ticket(path_pub_key,path_priv_key)

you can use RSA or DSA keys in pem or der format.

So, set the validuntil that the user will log out.

>>> validuntil = int(time.time())+ (24*60*60)

We will create a mod_auth_pubtkt compatible ticket. In the simplest
case no extra data is supplied.

>>> ticket = mod_auth_pubTicket.createTkt(userid,validuntil=validuntil)
>>>'uid=testUser;validuntil=1343379094;cip=0.0.0.0;sig=MC0CFQCJexq0701MPIcUYHoacJCKCbor1gIUI+oPZElmsNY8/rmk069+ef/u47o='

The cookie itself should be base64 encoded. We will use the built-in
Cookie module here, your web framework may supply it's own mechanism.

>>> import Cookie, binascii
>>> cookie = Cookie.SimpleCookie()
>>> cookie['auth_tkt'] = binascii.b2a_base64(ticket).strip()
>>> print cookie
Set-Cookie: auth_tkt=dWlkPXRlc3RVc2VyO3ZhbGlkdW50aWw9MTM0MzM3OTA5NDtjaXA9MC4wLjAuMDtzaWc9TUMwQ0ZEK1RibmpjMi91OEdjZVBGMm1MK24xTXk5bjRBaFVBalBFYTRDZ1RORHhMV2dlWjZTVjhjSGN3S3pRPQ==


Ticket validation
-----------------

First the ticket has to be read from the cookie and unencoded:

>>> ticket = binascii.a2b_base64(cookie['auth_tkt'].value)
>>> ticket
'uid=testUser;validuntil=1343379094;cip=0.0.0.0;sig=MC0CFQCJexq0701MPIcUYHoacJCKCbor1gIUI+oPZElmsNY8/rmk069+ef/u47o='

The server that invoke validateTkt and open a session cookie need at
least public Key. Init the Ticket object:

>>> from mod_auth import SignedTicket
>>> mod_auth_pubTicket = SignedTicket(path_pub_key)
## if you init with public key , SignedTicket can only validate and not create

next step is to validate:

>>> mod_auth_pubTicket.validateTkt(ticket)
>>> (u'testUser', [], [], 1343380332)

If the ticket is valid with valid sign and not expired , validateTkt
return all information about logged user else raise an Exception (see
function documentation for detail)


Tokens and user data
--------------------

The format allows for optional user data and tokens. For detail you
can see the test.py into mod_auh module, where there are some use test
of this class. Here an example:

>>> # Init SignedTicket object
>>> signTicket = SignedTicket('./DSApubkey.pem','./DSAprivkey.pem')

>>> #USER DATA
>>> userid = 'TestUser'
>>> tokens = ('role1', 'role2')
>>> userdata = ('testuser@mail.com','Italy','Bologna')
>>> cip = '127.0.0.1'
>>> # ticket is valdi until 24h from now
>>> validuntil = int(time.time())+ (24*60*60)
>>> #END USERDATA

>>> ticket = signTicket.createTkt(userid,tokens,userdata,cip,validuntil)


Simple use
**********

To start with mod_auth Library you can use Simple function to create
and validate Ticket. They based on mod_auth_tkt cookie authentication
and work with minimum set of attribute , SECRET and USERID. SECRET
have to be shared with all server where you intend to use tickets
system authetication. Example of use:

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

static mod_auth.createSimpleTicket(secret, userid, tokens=(), user_data=())

   Simple way to use mod_auth_tkt cookie authentication. To create a
   ticket it need only of SECRET and userid.

   Arguments:

      "secret" (string):
         secret key.

      "userid" (string):
         Unique user identifier.

   Optional arguments:

      "tokens" (tupla):
         tokens list.

      "user_data" (tupla):
         user data list

   Return:

      "ticket" (string):
         mod_auth_ticket format.

static mod_auth.validateSimpleTicket(secret, ticket)

   Simple way to use mod_auth_tkt cookie authentication. To validate a
   ticket it need only of SECRET and ticket.

   Arguments:

      "secret" (string):
         secret key.

      "ticket" (string):
         Ticket string value.

   Return:

      "fields" (tupla):
         ticket's fields format (userid, tocken, userdata, validuntil)


SignedTicket
************

class class mod_auth.mod_auth.SignedTicket(pub_key_Path, priv_key_Path=None)

   Mod_auth_pubtkt style cookie authentication class.

   validateTkt(ticket, now=None, encoding='utf8')

      Parse and verify auth_pubtkt ticket.

      Returns tupla with ticket's fields format: (userid, tocken,
      userdata, validuntil)

      "TicketParseError" exceptions can be raised in case of invalid
      ticket format or signature verification failure.

      "TicketExpired" exceptions raised if ticket expire.

      Arguments:

         "ticket" (string):
            Ticket string value.

         "now" (string):
            Timestamp of client datetime, if not set , server
            timestamp is used.

         "encoding":
            encoding of the data into ticket

      Return:

         "fields" (tupla):
            ticket's fields format (userid, tocken, userdata,
            validuntil)

   createTkt(userid, tokens=(), user_data=(), cip='0.0.0.0', validuntil=None, encoding='utf8')

      Create mod_auth_pubtkt ticket.

      Returns a valid ticket string.

      Arguments:

         "userid" (string):
            Unique user identifier.

      Optional arguments:

         "tokens" (tupla):
            tokens list.

         "user_data" (tupla):
            user data list

         "cip" (string):
            user client ip.

         "validuntil" (string):
            timestamp of ticket expiration.

         "encoding" :
            encoding of the data into ticket

      Return:

         "ticket" (string):
            mod_auth_pubtkt signed ticket format.


Ticket
******

class class mod_auth.mod_auth.Ticket(secret)

   Mod_auth_tkt style cookie authentication class.

   validateTkt(ticket, cip='0.0.0.0', now=None, encoding='utf8')

      To validate, a new ticket is created from the data extracted
      from cookie and the shared secret. The two digests are compared
      and timestamp checked.

      Successful validation returns a tupla with ticket's fields
      format: (userid, tocken, userdata, validuntil)

      "BadTicket" exceptions can be raised in case of invalid ticket
      format or digest verification failure.

      "TicketExpired" exceptions raised if ticket expire.

      Arguments:

         "ticket" (string):
            Ticket string value.

         "cip" (string):
            if createtkt was set client ip, here it need too, because
            it validate the digest.

         "now" (string):
            Timestamp of client datetime, if not set , server
            timestamp is used.

         "encoding":
            encoding of the data into ticket

      Return:

         "fields" (tupla):
            ticket's fields format (userid, tocken, userdata,
            validuntil)

   createTkt(userid, tokens=(), user_data=(), cip='0.0.0.0', validuntil=None, encoding='utf8')

      Create mod_auth_pubtkt ticket.

      Returns a valid ticket string.

      Arguments:

         "userid" (string):
            Unique user identifier.

      Optional arguments:

         "tokens" (tupla):
            tokens list.

         "user_data" (tupla):
            user data list

         "cip" (string):
            user client ip.

         "validuntil" (string):
            timestamp of ticket expiration.

         "encoding" :
            encoding of the data into ticket

      Return:

         "ticket" (string):
            mod_auth_ticket format.


Exception
*********

exception exception mod_auth.exception.BadSignature(ticket)

   Exception raised when a signature verification is failed

exception exception mod_auth.exception.BadTicket(ticket, msg='')

   Exception raised when a ticket has invalid format

exception exception mod_auth.exception.TicketExpired(ticket)

   Exception raised when a signature verification is failed

exception exception mod_auth.exception.TicketParseError(ticket, msg='')

   Base class for all ticket parsing errors


Indices and tables
******************

* *Index*

* *Module Index*

* *Search Page*
