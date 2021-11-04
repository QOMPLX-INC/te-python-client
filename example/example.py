#!/usr/bin/python3
#
# Example of write and read.
#

from mdtsdb import Mdtsdb
from mdtsdb.exceptions import Unauthorized, ConnectionError, GeneralError
import argparse, time, json, requests

HOST = "time-engine.qee.qomplxos.com"
PORT = 443
ISHTTPS = True
USER = "MyUser"
SECRET = "MySecret"
REQ_TIMEOUT = 600

#############################################################################

def main(args):
    try:
        user = Mdtsdb(host=HOST, port=PORT, admin_key=USER, secret_key=SECRET, timeout=REQ_TIMEOUT, is_https=ISHTTPS)

        # Creating a Swimlane with default retention policy (24h)
        swimlane_opts = {
            'has_expiration': True,
            'auto_label': True
        }
        (status, r) = user.new_appkey("Swimlane details", swimlane_opts)
        assert status == 'ok', (status, r)
        swimlane = Mdtsdb(host=HOST, port=PORT, app_key=str(r['key']), secret_key=str(r['secret_key']), timeout=REQ_TIMEOUT, is_https=ISHTTPS)

        # Send data
        t0 = int(time.time()) - 20
        multi_payload = [
            {
                "key": swimlane.app_key,
                "data": [{
                    "ns": t0,
                    "0": {
                        "value": 100
                    },
                    "1": {
                        "value": 100
                    }
                }]
            }
        ]
        (status, r) = user.insert(multi_payload)
        assert status == 'ok' and 'status' in r and r['status'] == 1, (status, json.dumps(r))

        # Read data
        (status, events) = swimlane.query("select $0-$1 end.")
        assert status == 'ok', events
        print(events['data'][0]['values'])

        print("OK!")

    except ConnectionError as e:
        print(e)
    except GeneralError as e:
        print(e)
    #except Unauthorized as e:
    #    print(e)
    except requests.exceptions.ConnectionError as e:
        print(e)

    finally:
        # Clean...
        if "swimlane" in locals():
            (status, r) = user.delete_appkey(swimlane.app_key)
            assert status == 'ok' and 'status' in r and r['status'] == 1, (status, r)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MDTSDB Python Client Test')
    parser.add_argument('-s','--server', help='MDTSDB server host', required=False, default=HOST)
    parser.add_argument('-p','--port', help='MDTSDB server port', required=False, default=PORT)
    parser.add_argument('--http', help='Use http scheme', required=False, action='store_true')
    parser.add_argument('--user', help='MDTSDB User key', required=False)
    parser.add_argument('--secret', help='MDTSDB User secret', required=False)
    args = parser.parse_args()

    if args.server != None:
        HOST = args.server
    if args.port != None:
        PORT = int(args.port)
    if args.http:
        ISHTTPS = False
    if args.user != None:
        USER = args.user
    if args.secret != None:
        SECRET = args.secret

    main(args)

#############################################################################
