"""
This module implements the session cookie format from mod_auth_tkt_ and mod_auth_pubtkt_.
In this documentation show you how to use and integrate mod_auth library into your project.

Contributors:

Before start I want say a BIG TANKS to plone.session team for tkauth.py module. It help us to start with this library:

 plone-session: https://github.com/plone/plone.session/blob/master/plone/session/tktauth.py

And to Andrey Plotnikov for a easy implementation fo mod_auth_pubtkt

 auth_pubtkt: https://github.com/AndreyPlotnikov/auth_pubtkt

mod_auth_tkt style cookie authentication
========================================

Mod_auth library implements the session cookie format from mod_auth_tkt_, the class used is Ticket.
Now ``createTicket`` and ``validateTicket`` functions use the MD5_ based
double hashing scheme in the original mod_auth_tkt.

.. _mod_auth_tkt: http://www.openfusion.com.au/labs/mod_auth_tkt/
.. _mod_auth_pubtkt: https://neon1.net/mod_auth_pubtkt/index.html
.. _MD5: http://en.wikipedia.org/wiki/MD5
.. _HMAC: http://en.wikipedia.org/wiki/HMAC
.. _SHA-256: http://en.wikipedia.org/wiki/SHA-256
.. _SCS: http://www.scsitaly.com


Configuration
-------------
In mod_auth_tkt the protocol depends on a secret string shared between servers.
From time to time this string should be changed, so store it in a configuration file.

  >>> SECRET = 'b8fb7b6df0d64dd98b8ccd00577434d7'

The tickets are only valid for a limited time. Here we will use 24 hours

  >>> DEFAULT_TIMEOUT = 24*60*60


Ticket creation
---------------
The minimal set of attributes to create a ticket are composed only from a userid:

    >>> userid = 'testUser'

First stemp is to init Ticket object:

    >>> from mod_auth import Ticket
    >>> mod_auth_Ticket = Ticket(SECRET)

So, set the validuntil that the user will log out.

    >>> validuntil = int(time.time())+ (24*60*60)


We will create a mod_auth_tkt compatible ticket. In the simplest case no extra
data is supplied.

    >>> ticket = mod_auth_Ticket.createTkt(userid,validuntil=validuntil)
    >>>'b054eeab313d4b75e10f4fd4ddb36ecf50115dcctestUser!'

The cookie itself should be base64 encoded. We will use the built-in Cookie
module here, your web framework may supply it's own mechanism.

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

The server that invoke validateTkt and open a session cookie
need of the SECRET to validate the digest into ticket.

Init the Ticket object:

    >>> from mod_auth import Ticket
    >>> mod_auth_Ticket = Ticket(SECRET)

next step is to validate:

    >>> mod_auth_Ticket.validateTkt(ticket)
    >>> (u'testUser', (), u'', 1343315404)

If the ticket is valid and not expired , validateTkt return all information
about logged user else raise an Exception (see function documentation for detail)


Tokens and user data
--------------------

The format allows for optional user data and tokens. For detail you can see
the test.py into mod_auh module, where there are some use test of this class.
Here an example:

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

mod_auth_pubtkt_ is a module that authenticates a user based on a cookie
with a ticket that has been issued by a central login server and digitally signed
using either RSA or DSA. This means that only the trusted login server has the private key
required to generate tickets, while web servers only need the corresponding public key to verify them.

In mod_auth module is implemented  by SignedTicket class.

Configuration
-------------
BE CAREFUL!For your safety, please, if you use this module in your project,
generate new keys (DSA or RSA) , to do that see the section below:

From your unix shell.
DSA:

     openssl dsaparam -out dsaparam.pem 2048

     openssl gendsa -out privDSAkey.pem dsaparam.pem

     openssl dsa -in privDSAkey.pem -out pubDSAkey.pem -pubout

     The dsaparam.pem file is not needed anymore after key generation and can safely be deleted.

RSA:

     openssl genDSArsa -out privkey.pem 2048

     openssl rsa -in privDSAkey.pem -out pubkey.pem -pubout


Ticket creation
---------------
Like into Ticket class , the minimal set of attributes
to create a ticket are composed only by a userid:

    >>> userid = 'testUser'

First stemp is to init SignedTicket object with your keys:

    >>> from mod_auth import SignedTicket
    >>> mod_auth_pubTicket = Ticket(path_pub_key,path_priv_key)

you can use RSA or DSA keys in pem or der format.

So, set the validuntil that the user will log out.

    >>> validuntil = int(time.time())+ (24*60*60)

We will create a mod_auth_pubtkt compatible ticket. In the simplest case no extra
data is supplied.

    >>> ticket = mod_auth_pubTicket.createTkt(userid,validuntil=validuntil)
    >>>'uid=testUser;validuntil=1343379094;cip=0.0.0.0;sig=MC0CFQCJexq0701MPIcUYHoacJCKCbor1gIUI+oPZElmsNY8/rmk069+ef/u47o='

The cookie itself should be base64 encoded. We will use the built-in Cookie
module here, your web framework may supply it's own mechanism.

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

The server that invoke validateTkt and open a session cookie
need at least public Key.
Init the Ticket object:

    >>> from mod_auth import SignedTicket
    >>> mod_auth_pubTicket = SignedTicket(path_pub_key)
    ## if you init with public key , SignedTicket can only validate and not create

next step is to validate:

    >>> mod_auth_pubTicket.validateTkt(ticket)
    >>> (u'testUser', [], [], 1343380332)

If the ticket is valid with valid sign and not expired , validateTkt return all information
about logged user else raise an Exception (see function documentation for detail)

Tokens and user data
--------------------

The format allows for optional user data and tokens. For detail you can see
the test.py into mod_auh module, where there are some use test of this class.
Here an example:

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

"""

__author__ = 'Alfredo Saglimbeni'
__mail__ = 'repirro(at)gmail.com, as.aglimbeni(at)scsitaly.com'

from socket import inet_aton
from struct import pack
import hashlib
import time
import base64
from exception import *

###IMPORT FOR MOD_AUTHPUBTKT###
from M2Crypto import RSA, DSA

## DEFAULT CONFIGURATION
DEFAULT_TIMEOUT= 12*60*60
########################

###########################
#### MOD_AUTH_PUBTKT ######
###########################

class SignedTicket(object):
    """
    Mod_auth_pubtkt style cookie authentication class.
    """
    def __init__(self,pub_key_Path, priv_key_Path=None ):
        ##LOAD priv_key
        try:
            try:
                priv_key = RSA.load_key(priv_key_Path)
            except Exception, e:
                priv_key = DSA.load_key(priv_key_Path)

            if priv_key_Path is not None and isinstance(priv_key, RSA.RSA):
                pub_key = RSA.load_pub_key(pub_key_Path)
            else:
                pub_key = DSA.load_pub_key(pub_key_Path)

        except Exception, e:
            raise ValueError('Unknown key type: %s' % self.pub_key)

        self.priv_key = priv_key
        self.pub_key =  pub_key


    def __verify_sig(self, data, sig):
        """Verify ticket signature.

        Returns False if ticket is tampered with and True if ticket is good.

        Arguments:

        ``data``:
            Ticket string without signature part.

        ``sig``:
            Ticket's sig field value.

        """
        sig = base64.b64decode(sig)
        dgst = hashlib.sha1(data).digest()
        if isinstance(self.pub_key, RSA.RSA_pub):
            try:
                self.pub_key.verify(dgst, sig, 'sha1')
            except RSA.RSAError:
                return False
            return True
        elif isinstance(self.pub_key, DSA.DSA_pub):
            return not not self.pub_key.verify_asn1(dgst, sig)
        else:
            raise ValueError('Unknown key type: %s' % self.pub_key)

    def __calculate_sig(self,data):
        """Calculates and returns ticket's signature.

        Arguments:

        ``data``:
           Ticket string without signature part.

        """
        dgst = hashlib.sha1(data).digest()
        if isinstance(self.priv_key, RSA.RSA):
            sig = self.priv_key.sign(dgst, 'sha1')
            sig = base64.b64encode(sig)
        elif isinstance(self.priv_key, DSA.DSA):
            sig = self.priv_key.sign_asn1(dgst)
            sig = base64.b64encode(sig)
        else:
            raise ValueError('Unknonw key type: %s' % self.priv_key)

        return sig

    def __create_ticket(self, uid, validuntil, ip=None, tokens=(),udata=(), graceperiod=None, extra_fields = () , encoding = "utf8"):
        """Returns signed mod_auth_pubtkt ticket.

        Mandatory arguments:

        ``uid``:
            The user ID. String value 32 chars max.

        ``validuntil``:
            A unix timestamp that describe when this ticket will expire. Integer value.

        Optional arguments:

        ``ip``:
           The IP address of the client that the ticket has been issued for.

        ``tokens``:
           List of authorization tokens.

        ``udata``:
           Misc user data.

        ``graceperiod``:
            A unix timestamp after which GET requests will be redirected to refresh URL.

        ``extra_fields``:
            List of (field_name, field_value) pairs which contains addtional, non-standard fields.

        ``encoding``:
            Encodign of the data.
        """

        uid = uid.encode(encoding)
        v = 'uid=%s;validuntil=%d' % (uid, validuntil)
        if ip:
            v += ';cip=%s' % ip
        if tokens:
            v += ';tokens=%s' % ','.join(tokens).encode(encoding)
        if graceperiod:
            ##TODO not used in 1.0 version
            v += ';graceperiod=%d' % graceperiod
        if udata:
            v += ';udata=%s' % ','.join(udata).encode(encoding)
        for k,fv in extra_fields:
            ##TODO not userd in 1.0 version
            v += ';%s=%s' % (k,fv)
        v += ';sig=%s' % self.__calculate_sig(v)
        return v

    def __parse_ticket(self, ticket, encoding = 'utf8'):
        """Parse and verify auth_pubtkt ticket.

        Returns dict with ticket's fields.

        ``BadTicket`` and ``BadSignature`` exceptions can be raised
        in case of invalid ticket format or signature verification failure.

        Arguments:

        ``ticket``:
            Ticket string value.

        ``encoding``:
            encoding of the data into ticket
        """

        i = ticket.rfind(';')
        sig = ticket[i+1:]
        if sig[:4] != 'sig=':
            raise BadTicket(ticket)
        sig = sig[4:]
        data = ticket[:i]

        if not self.__verify_sig( data, sig):
            raise BadSignature(ticket)

        data =  data.decode(encoding)

        try:
            fields = dict(f.split('=', 1) for f in data.split(';'))
        except ValueError:
            raise BadTicket(ticket)

        if 'uid' not in fields:
            raise BadTicket(ticket, 'uid field required')

        if 'validuntil' not in fields:
            raise BadTicket(ticket, 'validuntil field required')

        try:
            fields['validuntil'] = int(fields['validuntil'])
        except ValueError:
            raise BadTicket(ticket, 'Bad value for validuntil field')

        if 'tokens' in fields:
            tokens = fields['tokens'].split(',')
            if tokens == ['']:
                tokens = []
            fields['tokens'] = tokens
        else:
            fields['tokens'] = ()

        if 'udata' in fields:
            udata = fields['udata'].split(',')
            if udata == ['']:
                udata = []
            fields['udata'] = udata
        else:
            fields['udata'] = ()

        if 'graceperiod' in fields:
            try:
                fields['graceperiod'] = int(fields['graceperiod'])
            except ValueError:
                raise BadTicket(ticket, 'Bad value for graceperiod field')

        return fields


    def validateTkt(self,ticket, now=None, encoding='utf8'):

        """Parse and verify auth_pubtkt ticket.

        Returns tupla with ticket's fields format:
        (userid, tocken, userdata, validuntil)

        ``TicketParseError`` exceptions can be raised in case of invalid
        ticket format or signature verification failure.

        ``TicketExpired`` exceptions raised if ticket expire.

        Arguments:

            ``ticket`` (string):
                Ticket string value.

            ``now`` (string):
                Timestamp of client datetime, if not set , server timestamp is used.

            ``encoding``:
                encoding of the data into ticket

        Return:

            ``fields`` (tupla):
                ticket's fields format (userid, tocken, userdata, validuntil)

        """
        try:
            parsed_ticket = self.__parse_ticket(ticket,encoding)
            ( validuntil , userid, cip, token_list, user_data) = parsed_ticket['validuntil'],  parsed_ticket['uid'], parsed_ticket['cip'] ,parsed_ticket['tokens'] ,parsed_ticket['udata']

            if now is None:
                now = time.time()
            if int(validuntil) > now:
                return userid,token_list,user_data,validuntil
            else:
                raise TicketExpired(ticket)
        except Exception, e:
            raise TicketParseError(ticket,'Validate error')



    def createTkt(self,userid, tokens=(), user_data=(), cip='0.0.0.0', validuntil=None, encoding='utf8' ):
        """
        Create mod_auth_pubtkt ticket.

        Returns a valid ticket string.

        Arguments:

            ``userid`` (string):
                Unique user identifier.

        Optional arguments:

            ``tokens`` (tupla):
                tokens list.

            ``user_data`` (tupla):
                user data list

            ``cip`` (string):
                user client ip.

            ``validuntil`` (string):
                timestamp of ticket expiration.

            ``encoding`` :
                encoding of the data into ticket

        Return:

            ``ticket`` (string):
                mod_auth_pubtkt signed ticket format.

        """
        if self.priv_key is None:
            raise Exception('Private key is not Loaded: you can only validate')
        if validuntil is None:
            validuntil = int(time.time()) + DEFAULT_TIMEOUT

        userid = userid.encode(encoding)

        #TODO graceperiod and extra_field is not used in 1.0 version
        ticket=self.__create_ticket(userid,validuntil,cip,tokens,user_data,encoding=encoding)

        return ticket

###########################
###//END:MOD_AUTH_PUBTKT###
###########################

#######################
#### MOD_AUT_TKT ######
#######################
class Ticket(object):
    """
    Mod_auth_tkt style cookie authentication class.
    """
    def __init__(self, secret):

        self.secret=secret

    def __mod_auth_tkt_digest(self, data1, data2):
        digest0 = hashlib.md5(data1 + self.secret + data2).hexdigest()
        digest = hashlib.md5(digest0 + self.secret).hexdigest()
        return digest

    def __splitTicket(self,ticket, encoding='utf8'):
        digest = ticket[:32]
        val = ticket[32:40]
        if not val:
            raise ValueError
        timestamp = int(val, 16) # convert from hexadecimal+

        parts = ticket[40:].decode(encoding).split("!")

        if len(parts) == 2:
            userid, user_data = parts
            tokens = ()
            if len(user_data)>0:
                user_data = tuple(user_data.split(','))

        elif len(parts) == 3:
            userid, token_list, user_data = parts
            tokens = tuple(token_list.split(','))
            user_data = tuple(user_data.split(','))
        else:
            raise ValueError

        return digest, userid, tokens, user_data, timestamp

    def createTkt( self, userid, tokens=(), user_data=(), cip='0.0.0.0', validuntil=None, encoding='utf8'):
        """
        Create mod_auth_pubtkt ticket.

        Returns a valid ticket string.

        Arguments:

            ``userid`` (string):
                Unique user identifier.

        Optional arguments:

            ``tokens`` (tupla):
                tokens list.

            ``user_data`` (tupla):
                user data list

            ``cip`` (string):
                user client ip.

            ``validuntil`` (string):
                timestamp of ticket expiration.

            ``encoding`` :
                encoding of the data into ticket

        Return:

            ``ticket`` (string):
                mod_auth_ticket format.

        """
        if validuntil is None:
            validuntil = int(time.time()) + DEFAULT_TIMEOUT

        userid = userid.encode(encoding)

        ##OLD VERSION WITHOUT DSA SIGN
        token_list = ','.join(tokens).encode(encoding)

        user_list = ','.join(user_data).encode(encoding)

        # ip address is part of the format, set it to 0.0.0.0 to be ignored.
        # inet_aton packs the ip address into a 4 bytes in network byte order.
        # pack is used to convert timestamp from an unsigned integer to 4 bytes
        # in network byte order.
        data1 = inet_aton(cip) + pack("!I", validuntil)
        data2 = '\0'.join((userid, token_list, user_list))

        digest = self.__mod_auth_tkt_digest(data1, data2)

        # digest + timestamp as an eight character hexadecimal + userid + !
        ticket = "%s%08x%s!" % (digest, validuntil, userid)

        if tokens:
            ticket += token_list + '!'
        if user_data:
            ticket += user_list

        return ticket




    def validateTkt(self, ticket, cip='0.0.0.0', now=None, encoding='utf8'):
        """
        To validate, a new ticket is created from the data extracted from cookie
        and the shared secret. The two digests are compared and timestamp checked.

        Successful validation returns a tupla with ticket's fields format:
        (userid, tocken, userdata, validuntil)

        ``BadTicket`` exceptions can be raised in case of invalid
        ticket format or digest verification failure.

        ``TicketExpired`` exceptions raised if ticket expire.

        Arguments:

            ``ticket`` (string):
                Ticket string value.

            ``cip`` (string):
                if createtkt was set client ip, here it need too, because it validate the digest.

            ``now`` (string):
                Timestamp of client datetime, if not set , server timestamp is used.

            ``encoding``:
                encoding of the data into ticket

        Return:

            ``fields`` (tupla):
                ticket's fields format (userid, tocken, userdata, validuntil)
        """
        try:


            (digest, userid, tokens, user_data, validuntil) = data = self.__splitTicket(ticket)
            new_ticket = self.createTkt(userid, tokens, user_data, cip, validuntil, encoding)
            if new_ticket[:32] == digest:

                if now is None:
                    now = time.time()
                if validuntil > now:
                    return data[1:]

        except Exception, e:
            raise BadTicket(ticket,'ticket is not valid.')

        raise TicketExpired(ticket)


#######################
## //END:MOD_AUT_TKT ##
#######################


#######################
##### EASY USE ########
#######################


def createSimpleTicket(secret, userid, tokens=(), user_data=()):
    """
    Simple way to use mod_auth_tkt cookie authentication.
    To create a ticket it need only of SECRET and userid.

    Arguments:

        ``secret`` (string):
            secret key.

        ``userid`` (string):
            Unique user identifier.

    Optional arguments:

        ``tokens`` (tupla):
            tokens list.

        ``user_data`` (tupla):
            user data list

    Return:

        ``ticket`` (string):
            mod_auth_ticket format.

    """
    ticket = Ticket(secret)

    #generate ticket with user information
    return ticket.createTkt(userid,tokens,user_data)

def validateSimpleTicket(secret, ticket):
    """
    Simple way to use mod_auth_tkt cookie authentication.
    To validate a ticket it need only of SECRET and ticket.

    Arguments:

        ``secret`` (string):
            secret key.

        ``ticket`` (string):
            Ticket string value.

    Return:

        ``fields`` (tupla):
            ticket's fields format (userid, tocken, userdata, validuntil)

    """
    # init Ticket with secret key
    simpleticket = Ticket(secret)

    return ticket.validateTkt(simpleticket)



