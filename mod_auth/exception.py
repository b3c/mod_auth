__author__ = 'Alfredo Saglimbeni'
__mail__ = 'repirro(at)gmail.com, a.saglimbeni(at)scsitaly.com'


class TicketParseError(Exception):
    """Base class for all ticket parsing errors"""

    def __init__(self, ticket, msg=''):
        self.ticket = ticket
        self.msg = msg

    def __str__(self):
        return 'Ticket parse error: %s  (%s)' % (self.msg, self.ticket)


class BadTicket(TicketParseError):
    """Exception raised when a ticket has invalid format"""

    def __init__(self, ticket, msg=''):
        if not msg:
            msg = 'Invalid ticket format'
        super(self.__class__, self).__init__(ticket, msg)


class BadSignature(TicketParseError):
    """Exception raised when a signature verification is failed"""

    def __init__(self, ticket):
        super(self.__class__, self).__init__(ticket, 'Bad signature')

class TicketExpired(TicketParseError):
    """Exception raised when a signature verification is failed"""

    def __init__(self, ticket):
        super(self.__class__, self).__init__(ticket, 'Ticket Expired')

