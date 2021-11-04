#
# exceptions.py - TimeEngine Python client exceptions
# Copyright 2015-2021 -- QOMPLX, Inc. -- All Rights Reserved.  No License Granted.
#

#############################################################################

class NotFound(Exception):

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

class Unauthorized(Exception):

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

class Forbidden(Exception):

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

class ApiError(Exception):
    """The base class for TimeEngine exceptions"""

    def __init__(self, error):
        self.error = error

    def __str__(self):
        return str(self.error)

class ConnectionError(ApiError):
    """Connection problems"""
    pass

class PermissionDeniedError(ApiError):
    """1xxx: Incorrect authentication or request fails the permission checks"""
    pass

class ServiceTimeoutError(ApiError):
    """2xxx: Service cannot complete the request due to overload protection and/or timeouts caused by bulky operations"""
    pass

class ProtocolError(ApiError):
    """3xxx: Error in protocol between client/server, e.g.: wrong method name, invalid parameter value"""
    pass

class QlError(ApiError):
    """4xxx: Interpretation of query language script fails"""
    pass

class BadRequestError(ApiError):
    """5xxx: Request violates server limitations or refers to invalid entities"""
    pass

class DbError(ApiError):
    """6xxx: DB layer error"""
    pass

class AmqpError(ApiError):
    """7xxx: AMQP error"""
    pass

class DataFormatError(ApiError):
    """8xxx: Data sent to be stored have invalid format"""
    pass

class GeneralError(ApiError):
    """9xxx: Problems with general availability of the service or error without details useful to the client side"""
    pass

#############################################################################

CodesMapping = {
    1: PermissionDeniedError,
    2: ServiceTimeoutError,
    3: ProtocolError,
    4: QlError,
    5: BadRequestError,
    6: DbError,
    7: AmqpError,
    8: DataFormatError,
    9: GeneralError
}

def raise_by_code(response):
    if isinstance(response, tuple) and len(response) == 2:
        (status, details) = response
        if status == 'error':
            _raise_by_code(details)
    return response

def _raise_by_code(details):
    if isinstance(details, dict) and 'code' in details and 'message' in details:
        code = details['code'] / 1000 if 'code' in details else 9
        raise CodesMapping[9 if code < 1 or code > 9 else code](details['message'])
    else:
        raise GeneralError(str(details))

#############################################################################
