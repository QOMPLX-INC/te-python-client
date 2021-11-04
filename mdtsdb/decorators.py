#
# decorators.py - TimeEngine Python client decorators
# Copyright 2015-2021 -- QOMPLX, Inc. -- All Rights Reserved.  No License Granted.
#

#############################################################################

import time
from decorator import decorator
from requests.exceptions import ConnectTimeout
from mdtsdb.exceptions import ConnectionError as _ConnectionError, GeneralError, NotFound, Unauthorized, Forbidden

MAX_RETRY = 3
RETRY_DELAY = 3

@decorator
def handle_error(method, self, *args, **kargs):
    """Handle request errors"""
    error = ''
    for _ in range(MAX_RETRY):
        try:
            response = method(self, *args, **kargs)
        except ConnectTimeout as e:
            error = e
            time.sleep(RETRY_DELAY)
            continue
        else:
            if response.status_code == 404:
                raise NotFound(response.reason)
            elif response.status_code == 401:
                raise Unauthorized(response.reason)
            elif response.status_code == 403:
                raise Forbidden(response.reason)
            elif response.status_code >= 400:
                raise GeneralError(response.reason)
            else:
                return response
    raise _ConnectionError(error)

#############################################################################
