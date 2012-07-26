__author__ = 'Alfredo Saglimbeni'
__mail__ = 'repirro(at)gmail.com, as.aglimbeni(atscsitaly.com'

from mod_auth import *
from M2Crypto.RSA import gen_key
import os
import uuid
import subprocess

def mod_auth_pub_tkt_Test():

    #########################################
    ##TEST mod_auth_pubtkt with RSA keys pair
    #########################################
    print '#### TEST mod_auth_pubtkt with RSA keys pair : START!\n'

    print 'Please generate Keys:'
    subprocess.call('openssl genrsa -out RSAprivkey.pem 1024',shell=True)
    subprocess.call('openssl rsa -in RSAprivkey.pem -out RSApubkey.pem -pubout',shell=True)
    print 'RSA keys generate!'

    # Init SignedTicket object
    signTicket = SignedTicket('./RSApubkey.pem','./RSAprivkey.pem')


    #USER DATA

    userid = 'TestUser'
    tokens = ('role1', 'role2')
    userdata = ('testuser@mail.com','Italy','Bologna')
    cip = '127.0.0.1'
    # ticket is valdi until 24 from now
    validuntil = int(time.time())+ (24*60*60)

    #END USERDATA

    ticket = signTicket.createTkt(userid,tokens,userdata,cip,validuntil)
    print "Ticket with RSA keys generate correctly: %s" %ticket

    print 'If you want send ticket over url or save it into cookie , it need to be encoded.'
    #If you want send ticket over url or save it into cookie , it need to be encoded.
    ticket64 = base64.b64encode(ticket)

    print "Ticket base64 encoded: %s" %ticket64

    validate = signTicket.validateTkt(ticket)

    print "Ticket valid:%s " %str(validate)

    os.remove('./RSApubkey.pem')
    os.remove('./RSAprivkey.pem')

    print '#### TEST mod_auth_pubtkt with RSA keys pair : END!'
    #########################################
    ##TEST mod_auth_pubtkt with DSA keys
    #########################################

    print '#### TEST mod_auth_pubtkt with DSA keys: START!'

    subprocess.call('openssl dsaparam -out dsaparam.pem 1024',shell=True)
    subprocess.call('openssl gendsa -out DSAprivkey.pem dsaparam.pem',shell=True)
    subprocess.call('openssl dsa -in DSAprivkey.pem -out DSApubkey.pem -pubout',shell=True)
    print 'DSA keys generate!'

    # Init SignedTicket object
    signTicket = SignedTicket('./DSApubkey.pem','./DSAprivkey.pem')

    #USER DATA

    userid = 'TestUser'
    tokens = ('role1', 'role2')
    userdata = ('testuser@mail.com','Italy','Bologna')
    cip = '127.0.0.1'
    # ticket is valdi until 24 from now
    validuntil = int(time.time())+ (24*60*60)

    #END USERDATA

    ticket = signTicket.createTkt(userid,tokens,userdata,cip,validuntil)
    print "Ticket with DSA keys generate correctly: %s" %ticket

    print 'If you want send ticket over url or save it into cookie , it need to be encoded.'
    #If you want send ticket over url or save it into cookie , it need to be encoded.
    ticket64 = base64.b64encode(ticket)

    print "Ticket base64 encoded: %s" %ticket64

    validate = signTicket.validateTkt(ticket)

    print "Ticket valid:%s " %str(validate)

    os.remove('./DSApubkey.pem')
    os.remove('./DSAprivkey.pem')
    os.remove('./dsaparam.pem')

    print '#### TEST mod_auth_pubtkt with DSA keys pair : END!'


def mod_auth_tkt_Test():

    #########################################
    ##TEST mod_auth_tkt with Secret key and MD5 digest
    #########################################

    print '#### TEST mod_auth_tkt with Secret key and MD5 digest : START!'

    Secret = str(uuid.uuid4().hex)

    print 'Secret generate: %s' %Secret

    # Init SignedTicket object
    simpleTicket = Ticket(Secret)

    #USER DATA

    userid = 'TestUser'
    tokens = ('role1', 'role2')
    userdata = ('testuser@mail.com','Italy','Bologna')
    cip = '127.0.0.1'
    # ticket is valdi until 24 from now
    validuntil = int(time.time())+ (24*60*60)

    #END USERDATA

    ticket = simpleTicket.createTkt(userid,tokens,userdata,cip,validuntil)
    print "Ticket with RSA keys generate correctly: %s" %ticket

    print 'If you want send ticket over url or save it into cookie , it need to be encoded.'
    #If you want send ticket over url or save it into cookie , it need to be encoded.
    ticket64 = base64.b64encode(ticket)

    print "Ticket base64 encoded: %s" %ticket64

    validate = simpleTicket.validateTkt(ticket,cip)

    print "Ticket valid:%s " %str(validate)


    print '#### TEST mod_auth_tkt with Secret key and MD5 digest : END!'

if __name__ == '__main__':
    print ">>>MOD_AUTH LIBRARY TEST<<<\n"
    print "\n>>>START TEST1 : \n"
    mod_auth_pub_tkt_Test()

    print "\n>>>START TEST2 : \n"

    mod_auth_tkt_Test()

    print "\n>>>MOD_AUTH LIBRARY TESTEND<<<\n"