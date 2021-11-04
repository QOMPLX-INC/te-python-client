#
# client.py - TimeEngine Python Client
# Copyright 2015-2021 -- QOMPLX, Inc. -- All Rights Reserved.  No License Granted.
#

#############################################################################

import requests, json, urllib, zlib, sys
from collections import OrderedDict
import logging, types, time, hmac, hashlib, base64, bson

from mdtsdb.decorators import handle_error
from mdtsdb.exceptions import NotFound, raise_by_code
from mdtsdb.etf import term_to_binary

PY3 = sys.version_info >= (3,5,0)

MDTSDB_AUTH2 = 'MDTSDB-HMAC-SHA256 '
MDTSDB_AUTH2_STREAMING = 'MDTSDB-STREAMING-HMAC-SHA256 '
def maybe_encode(s):
    try:
        return s.encode('utf-8') if isinstance(s, unicode) else s
    except NameError:
        return s.encode('utf-8') if isinstance(s, str) else s

class HttpClient(object):
    """HTTP client with base URL
    """

    admin_methods = {
        'newApiKey', 'assureApiKey', 'deleteApiKey',
        'newAdminKey', 'assureAdminKey', 'deleteAdminKey'
    }
    common_data_methods = {'setData', 'ping', 'cmd_ext'}
    kml_keys = ('id', 'alias_tag', 'ns', 'ms_attr', 'ms_tag', 'val', 'val_tag', 'base64')

    def __init__(self, host='127.0.0.1', port=8080, app_key='', admin_key='', secret_key='', options={},
                       timeout = 30, is_https = False, auth_url = None, client_id = None, client_secret = None):
        """Initialize base URL.

        :param host: hostname / IP address
        :param port: port
        """
        scheme = 's' if is_https else ''
        self.base_url = 'http{0}://{1}:{2}/'.format(scheme, host, port)
        self.ws_base_url = 'ws{0}://{1}:{2}/'.format(scheme, host, port)
        self.session = requests.Session()
        self.options = options
        self.app_key = app_key
        self.admin_key = admin_key
        self.secret_key = maybe_encode(secret_key) if PY3 else b'{}'.format(secret_key)
        self.timeout = timeout
        self.access_token = None
        self.access_token_type = None
        self.client_id = None
        self.client_secret = None
        self.auth_url = None
        self.is_https = is_https

        if auth_url and client_id and client_secret:
            self.keycloak_load_access_token(auth_url, client_id, client_secret)

    def keycloak_set_access_token(self, access_token, access_token_type = "Bearer"):
        token_parts = access_token.split(".")
        token_info = token_parts[1]
        if token_info[-2:] != "==":
            token_info = token_parts[1] + "=="
        token_info_str = base64.b64decode(token_info)
        if token_info_str:
            token_info_str = token_info_str.decode('ascii')
        access_token_obj = json.loads(token_info_str)
        #
        mdtsdb_admin_key = access_token_obj.get("clientId")
        if not mdtsdb_admin_key:
            return 'error', "unexpected response: undefined 'clientId'\n" + json.dumps(access_token_obj)
        self.app_key = ''
        self.admin_key = ''
        self.secret_key = ''
        if mdtsdb_admin_key:
            self.admin_key = mdtsdb_admin_key
        self.access_token = access_token
        self.access_token_type = access_token_type
        return 'ok'

    def keycloak_load_access_token(self, url, client_id, client_secret):
        http_method = requests.Session().post
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "cache-control": "no-cache"
        }
        data = "client_id=%s&client_secret=%s&grant_type=client_credentials" % (client_id, client_secret)
        ret = http_method(url = url, data = data, headers = headers, timeout = self.timeout) #
        if ret.status_code != 200:
            return 'error', ret.text
        resp = json.loads(ret.text)
        access_token = resp.get("access_token")
        access_token_type = resp.get("token_type", "Bearer")
        if not access_token:
            return 'error', "unexpected response: undefined 'access_token'\n" + ret.text
        self.auth_url = url
        self.client_id = client_id
        self.client_secret = client_secret
        return self.keycloak_set_access_token(access_token, access_token_type)

    def keycloak_update_access_token(self):
        if not self.auth_url: return False
        if not self.client_id: return False
        if not self.client_secret: return False
        res = self.keycloak_load_access_token(self.auth_url, self.client_id, self.client_secret)
        return res == 'ok'

    def call_method(self, method, content, args={}):
        response = self._call_method(method, content, args)
        resp = self.parse_response(response)
        if self._is_response_authorization_error(resp):
            response = self._call_method(method, content, args)
            resp = self.parse_response(response)
        return resp

    def call_method_chunked(self, method, content, args={}):
        response = self._call_method_chunked(method, content, args)
        resp = self.parse_response_chunked(response)
        if self._is_response_authorization_error(resp):
            response = self._call_method_chunked(method, content, args)
            resp = self.parse_response_chunked(response)
        return resp

    def ql_query(self, query, args={}):
        response = self._ql_query(query, args)
        resp = self.parse_response(response, args)
        if self._is_response_authorization_error(resp):
            response = self._ql_query(query, args)
            resp = self.parse_response(response, args)
        return resp

    def ql_query_raw(self, query, args={}):
        r = self._ql_query(query, args)
        return ('ok', r.content) if r.status_code == 200 else ('error', r.status_code)

    def kml_query(self, content, args={}):
        response = self._kml_query(content, args)
        resp = self.parse_response(response)
        if self._is_response_authorization_error(resp):
            response = self._kml_query(content, args)
            resp = self.parse_response(response)
        return resp

    def delayed_query(self, uuid, args={}):
        response = self._delayed_query(uuid, args)
        resp = self.parse_response(response)
        if self._is_response_authorization_error(resp):
            response = self._delayed_query(uuid, args)
            resp = self.parse_response(response)
        return resp

    ##
    def _is_response_authorization_error(self, resp):
        if not isinstance(resp, tuple):
            return False
        (ok, msg) = resp
        if ok == 'ok':
            return False
        if not isinstance(msg, dict):
            return False
        if msg.get("code") != 1001:
            return False
        if msg.get("message") != "authorization error":
            return False
        return self.keycloak_update_access_token()

    def get_stream_errors(self, parsed_stream):
        """Gets error replies from a parsed stream of query results.

        :param parsed: server response to a query executed with parameter stream=true
        """
        return [r for (ok, r) in parsed_stream if ok == "error"]

    def merge_stream_values(self, parsed_stream, merge = True):
        """Converts a parsed stream of query results into a sequence of values,
           retrieved from every part of results.

        :param parsed: server response to a query executed with parameter stream=true
        :param merge: whether to merge result values into one continuous sequence
        """
        if len(parsed_stream) == 1:
            (status, r) = parsed_stream[0]
            assert status == 'ok' and 'data' in r, "Expect valid query results"
            return r['data'][0]['values']
        else:
            (status, r) = self.jsonseq_to_json(parsed_stream)
            assert status == 'ok' and all('data' in resp for resp in r), "Expect valid query results"
            r = [resp['data'][0]['values'] for resp in r]
            if not merge:
                return r
            values = r[0]
            for d in r[1:]:
                for alias, v in d.items():
                    if alias in values:
                        if isinstance(v, dict):
                            values[alias].update(v)
                        else:
                            values[alias] += v
                    elif isinstance(v, list):
                        values[alias] = v
                    else:
                        raise ValueError('Unexpected query response format')
            return values

    def jsonseq_to_json(self, parsed_stream):
        """When the server responses to a query executed with parameter stream=true
           with json-seq format, this method helps to convert the response to a tuple
           (status, results), where results is a list of error, postpone or ok responses.

        :param parsed_stream: server response to a query executed with parameter stream=true
        """
        recs, errs, postpone = [], [], []
        for (status, rec) in parsed_stream:
            if status == 'error':
                errs.append(rec)
            elif status == 'ok':
                recs.append(rec)
            elif status == 'postpone':
                postpone.append(rec)
            else:
                raise ValueError('unexpected response format')
        if len(errs) > 0:
            return 'error', errs
        elif len(postpone) > 0:
            return 'postpone', postpone
        else:
            return 'ok', recs

    def maybe_parse_json(self, r, args={}):
        if 'keep_order' in args and args['keep_order']:
            jp = lambda txt: json.loads(txt, object_pairs_hook=OrderedDict)
        else:
            jp = lambda txt: json.loads(txt)
        try:
            is_seq = 'content-type' in r.headers and r.headers['content-type'] == 'application/json-seq'
            if is_seq:
                lines = r.text.split('\x1E')
                return [self._parse_result(jp(line.strip()), len(line)) for line in lines[1:]]
            else:
                return self._parse_result(jp(r.text), len(r.text))
        except ValueError as ve:
            return [r.text] if is_seq else r.text

    def parse_response(self, r, args={}):
        if self.options.get('raise', None):
            r.raise_for_status()
            if r.text and isinstance(r.text, dict):
                return raise_by_code(self._parse_result(r.text))
            elif r.text:
                return raise_by_code(self.maybe_parse_json(r, args))
            raise_by_code(('error', 'unexpected format of server response'))
        else:
            if r.status_code != 200:
                return 'error', r.status_code
            elif r.text and isinstance(r.text, dict):
                return self._parse_result(r.text)
            elif r.text:
                return self.maybe_parse_json(r, args)
            return 'error', 'unexpected format of server response'

    def parse_response_chunked(self, r, args={}):
        if r.status_code == 200 and 'transfer-encoding' in r.headers and r.headers['transfer-encoding'] == 'chunked':
            keep_order = 'keep_order' in args and args['keep_order']
            for text in r.iter_lines():
                if text:
                    try:
                        text = text.decode() if PY3 and isinstance(text, bytes) else text
                        result = json.loads(text, object_pairs_hook=OrderedDict) if keep_order else json.loads(text)
                        yield self._parse_result(result, len(text))
                    except ValueError:
                        yield text
        else:
            yield self.parse_response(r, args)

    def _parse_result(self, r_text, r_text_len = None):
        if 'result' in r_text:
            if isinstance(r_text['result'], dict) and 'uuid' in r_text['result']:
                return 'postpone', r_text['result']['uuid']
            result = r_text['result']
            if r_text_len and isinstance(result, dict) and 'data' in result and isinstance(result['data'], list) and len(result['data']) > 0:
                d = result['data'][0]
                if 'ms' in d:
                    d['_qsz'] = r_text_len
            return 'ok', result
        elif 'error' in r_text:
            d = r_text['error']
            if d['message'] == 'the job is postponed':
                return 'postpone', d['details']['uuid']
            return 'error', d
        else:
            return 'error', 'protocol'

    def _construct_url(self, resources):
        return '/'.join(filter(lambda x: x != None, resources))

    def event_upload_url(self, resource=None):
        return self._construct_url(('api/v1/ingest', resource))

    def ql_url(self, resource=None, asyncv=None):
        return self._construct_url(('api/v1/ql', asyncv, resource))

    def make_auth_content(self, uri, method, payload_hash, content_type, user_key):
        secret_key = self.secret_key
        ts = str(int(time.time()) // 1000)
        msg = ''
        sk1, sk2 = None, None
        if PY3:
            for msg in [ts, method]:
                if isinstance(secret_key, str):
                    secret_key = bytes(secret_key, 'utf-8')
                secret_key = hmac.new(secret_key, maybe_encode(msg), hashlib.sha256).digest()
                if sk1:
                    sk2 = secret_key
                else:
                    sk1 = secret_key
            uri_ext = '/' + uri + '\n' + content_type + '\n' + payload_hash
            payload_digest = hashlib.sha256(maybe_encode(uri_ext)).hexdigest()
            msg = maybe_encode(ts) + b'\n' + user_key + b'\n' + maybe_encode(payload_digest)
        else:
            for msg in [ts, method]:
                secret_key = hmac.new(secret_key, msg, hashlib.sha256).digest()
            uri_ext = '/' + uri + '\n' + content_type + '\n' + payload_hash
            payload_digest = hashlib.sha256(uri_ext).hexdigest()
            msg = ts + '\n' + user_key + '\n' + payload_digest
        signature = hmac.new(secret_key, msg, hashlib.sha256).hexdigest()
        return signature

    def method_info(self, method, args={}):
        mode = args['mode'] if 'mode' in args else ''
        if method in self.common_data_methods:
            if mode == 'geo_events':
                quoted = urllib.parse.quote(self.app_key, safe='') if PY3 else urllib.quote(self.app_key, safe='')
                data_url = self.event_upload_url(quoted)
            else:
                data_url = self.event_upload_url()
            return (data_url, 'application/json', self.app_key or self.admin_key)
        elif method == 'ql':
            if mode == 'events':
                ql_url = self.ql_url()
                if 'ver' in args and args['ver'] == 2:
                    ql_url += '?v=2'
            elif mode == 'kml':
                ql_url = 'api/v1/ingest/kml'
            elif mode == 'result_events':
                ql_url = 'api/v1/result/events'
            else:
                ql_url = 'api/v1/result'
            return (ql_url, 'application/x-www-form-urlencoded', self.app_key or self.admin_key)
        elif method in self.admin_methods:
            return ('api/v1/admin', 'application/json', self.admin_key)
        else:
            return (self.ql_url(), 'application/x-www-form-urlencoded', self.app_key)

    def do_http(self, http_method, uri, payload, headers, method, user_key):
        signature = self._prepare_signature(uri, payload, headers, method, user_key)
        headers = self._do_sign(headers, method, user_key, signature)
        with http_method(url = self.base_url + uri, data = payload, headers = headers, timeout = self.timeout) as ret:
            return ret

    def _do_sign(self, headers, method, user_key, signature, auth_method = None):
        if self.access_token:
            access_token_type = self.access_token_type if self.access_token_type else "Bearer"
            headers['authorization'] = '%s %s' % (access_token_type, self.access_token)
            accesskey_info = self._prepare_accesskey_info(user_key)
            headers['x-mtdtsdb-authinfo'] = '%s%s %s %s,%s' % (auth_method or MDTSDB_AUTH2, user_key, signature, accesskey_info, method)
        else:
            accesskey_info = self._prepare_accesskey_info(user_key)
            headers['authorization'] = '%s%s %s %s,%s' % (auth_method or MDTSDB_AUTH2, user_key, signature, accesskey_info, method)
        return headers

    def _prepare_accesskey_info(self, user_key):
        return 's' if user_key == self.app_key else 'a' if user_key == self.admin_key else 'u'

    def _prepare_signature(self, uri, payload, headers, method, user_key):
        user_key = maybe_encode(user_key)
        payload_hash = hashlib.sha256(maybe_encode(payload)).hexdigest()
        content_type = headers['content-type'] or ''
        return self.make_auth_content(uri, method, payload_hash, content_type, user_key)

    @handle_error
    def _call_method(self, method, content, args={}):
        """Send POST request and return the response of the server method.

        :param method: server api method to call
        :param content: request data
        :param args: additional parameters of the request
        """
        if (not isinstance(content, dict) and not isinstance(content, str)) or not content:
            raise ValueError('Non-empty dictionary or a string is expected')
        (is_data_ep, url, headers, sign_key) = self._call_method_prepare_ep(method, args)
        payload = self._call_method_prepare_content(is_data_ep, content)
        return self.do_http(self.session.post, url, payload, headers, method, sign_key)

    @handle_error
    def _call_method_chunked(self, method, gen_content, args={}):
        """Send POST request using chunked transfer encoding and return the response of the server method.

        :param method: server api method to call
        :param content: request data
        :param args: additional parameters of the request
        """
        if isinstance(gen_content, dict) or isinstance(gen_content, str):
            return self._call_method(method, gen_content, args)
        (is_data_ep, url, headers, sign_key) = self._call_method_prepare_ep(method, args)
        signature = self._prepare_signature(url, '', headers, method, sign_key)
        headers = self._do_sign(headers, method, sign_key, signature, MDTSDB_AUTH2_STREAMING)
        return self.session.post(
            url = self.base_url + url,
            data = self._call_method_chunked_generator(is_data_ep, url, gen_content, headers, method, sign_key, signature),
            headers = headers,
            stream = True,
            timeout = self.timeout
        )

    def _call_method_chunked_generator(self, is_data_ep, uri, gen_content, headers, method, user_key, signature):
        for content in gen_content:
            payload = self._call_method_prepare_content(is_data_ep, content)
            if PY3:
                signature = self._prepare_signature(uri, b"".join([signature.encode('utf-8'), b' ', payload]), headers, method, user_key)
                yield b"".join([signature.encode('utf-8'), b' ', payload, b'\x1E'])
            else:
                signature = self._prepare_signature(uri, signature + ' ' + payload, headers, method, user_key)
                yield signature + ' ' + payload + '\x1E'

    def _call_method_prepare_ep(self, method, args={}):
        (url, content_type, sign_key) = self.method_info(method, args=args)
        is_data_ep = url == self.event_upload_url()
        headers = {'content-type': content_type}
        if is_data_ep:
            compression = self.options.get('compression', None)
            if compression == 'gzip':
                headers['content-encoding'] = 'gzip'
            elif compression == 'mdtsdb':
                headers = {'content-type': 'application/octet-stream', 'content-encoding': 'mdtsdb'}
            elif compression == 'bson':
                headers = {'content-type': 'application/octet-stream', 'content-encoding': 'bson'}
            elif compression == 'gzip-bson':
                headers = {'content-type': 'application/octet-stream', 'content-encoding': 'gzip-bson'}
        return (is_data_ep, url, headers, sign_key)

    def _call_method_prepare_content(self, is_data_ep, content):
        compression = self.options.get('compression', None)
        compression_level = self.options.get('compression_level', None)
        if isinstance(content, dict):
            if is_data_ep and compression == 'mdtsdb':
                payload = term_to_binary(content, compression_level)
            elif is_data_ep and compression == 'bson':
                payload = bson.dumps(content)
            elif is_data_ep and compression == 'gzip-bson':
                payload = bson.dumps(content)
            else:
                payload = json.dumps(content).encode() if PY3 else json.dumps(content)
        else:
            payload = content.encode() if PY3 else content
        gzip_compress = is_data_ep and (compression == 'gzip' or compression == 'gzip-bson')
        return zlib.compress(payload, compression_level or 6) if gzip_compress else payload

    @handle_error
    def _ql_query(self, query, args={}):
        """Send POST query language request and return the response of this server method.

        :param query: query language script to execute
        :param args: additional parameters of the request
        """
        params = {
            'q': maybe_encode(query),
            'key': maybe_encode(self.app_key),
            'adm': maybe_encode(self.admin_key),
            'stream': 1 if 'stream' in args and args['stream'] else 0
        }
        if 'async' in args and args['async']:
            params['async'] = 1
        payload = requests.compat.urlencode(params, doseq=True)
        method = 'ql'
        (url, content_type, sign_key) = self.method_info(method, args=args)
        return self.do_http(self.session.post, url, payload, {'content-type': content_type}, method, sign_key)

    @handle_error
    def _kml_query(self, kml_data, args={}):
        """Send POST KML/KMZ data upload request and return the response of this server method.

        :param kml_data: KML or KMZ data
        :param args: additional parameters of the request with default geo-information values
        """
        if 'base64' in args and args['base64'] == 'true':
            if PY3 and isinstance(kml_data, str):
                kml_data = kml_data.encode('ascii')
            q = base64.b64encode(kml_data)
        else:
            q = maybe_encode(kml_data)
        content = {'q': q, 'key': maybe_encode(self.app_key)}
        for k in self.kml_keys:
            if k in args:
                content[k] = maybe_encode(args[k])
        payload = requests.compat.urlencode(content, doseq=True)
        method = 'ql'
        (url, content_type, sign_key) = self.method_info(method, args = {'mode': 'kml'})
        return self.do_http(self.session.post, url, payload, {'content-type': content_type}, method, sign_key)

    @handle_error
    def _delayed_query(self, uuid, args={}):
        """Send POST stored results request and return the response of this server method.

        :param uuid: identifier of the stored data
        :param args: additional parameters of the request
        """
        key = self.admin_key if self.app_key is None or self.app_key == '' else self.app_key
        payload = requests.compat.urlencode({
            'uuid': maybe_encode(uuid),
            'key': maybe_encode(key)
        }, doseq=True)
        method = 'ql'
        (url, content_type, sign_key) = self.method_info(method, args=args)
        return self.do_http(self.session.post, url, payload, {'content-type': content_type}, method, sign_key)


class Mdtsdb(HttpClient):

    """TimeEngine connection manager
    """

    def send_events_data(self, t0, sensor_data):
        """Uploads data to server.

           | Data swimline is determined by the application key.
           | Several sensor values can be sent at once, so that sensor_data argument is a dictionary
           | that maps a sensor identifier to a sensor value, e.g.:
           | ``{'ns': 1421507438, '1': 10, '2': 20, '10': 100}``

           Sensor value is either scalar value (numeric or binary string), or a list of fields of
           the json structure encoded in mochijson2:encode() format.

        :param t0: unix timestamp
        :param sensor_data: dictionary, mapping a sensor identifier to the sensor value
        """
        p = {'ns': t0}
        p.update(sensor_data)
        return self._send_data('events', p)

    def send_events_data_vector(self, time_series):
        """The compatibility wrapper for :func:`~client.Mdtsdb.insert`.
        """
        return self.insert(time_series)

    def insert(self, time_series):
        """Uploads data to server.

           | There are two modes of the method: batch multi-swimlane send and one-swimlane send.
           | In the one-swimlane send data swimline is determined by the application key of the client.
           | Several time points can be sent at once in a list of dictionaries, where each list item
           | maps a sensor identifier to a sensor value and holds a unix timestamp under 'ns' key, e.g.:
           | ``[{'ns': 1421507438, '1': 10}, {'ns': 1421507439, '1':10, '2':20}]``

           | In the case of batch multi-swimlane send, the application key of the client is used only
           | for authentication. Destination swimlanes are listed in the method 'params' field.
           | Sensor data must be formatted as the following:
           | ``[{'key': 'swimlane1', 'data': ...}, {'key': 'swimlane2', 'data': ...}, ...]``,
           | where 'data' format is the same as sensor data for one-swimlane send data version of the method.

           | Batch multi-swimlane send can be implemented without references to destination application keys,
           | using just partition and series keys (or tags). Data points having different combination of values
           | of these keys will be forwarded to different swimlanes (by partition keys) and sensors (by series keys).
           | Series keys are optional. Tags will be used instead of series keys, or all data points will be wrtitten
           | to time series of the sensor no. 0 if neither series not tag keys are present.
           | In this case sensor data must be formatted as the following:
           | ``[{'partition': ..., 'data': {'ns': ..., 'series': ..., 'tags': ..., 'value': ...}}, ...]``, or
           | ``[{'partition': ..., 'data': {'ns': ..., <sensor no/label>: <data point>, <sensor no/label>: <data point>}}, ...]``

           This method can be called by admin client, so that admin key/secret key are used for authentication.
           Only batch multi-swimlane send is available for sending data by the admin client.

           Sensor value is either scalar value (numeric or bianry string), or a list of fields of
           the json structure encoded in mochijson2:encode() format.

        :param time_series: dictionary, mapping a sensor identifier to the sensor value
        """
        return self._send_data('events', time_series)

    def send_events_geo_data(self, payload):
        """Uploads GeoJSON/TopoJSON/KML data to server.

           Data swimline is determined by the application key. Payload is a string of
           either GeoJSON, TopoJSON or KML format.

           Please see additional details about sent data in README.

        :param payload: string in GeoJSON, TopoJSON or KML format
        """
        return self.call_method('setData', payload, args={'mode': 'geo_events'})

    def send_kml_file(self, filepath, default_params):
        """Uploads file in Keyhole Markup Language (KML/KMZ) format to the server.

        Additional parameters may hold several key-value records with predefined names to
        fill possible gaps in geo-information in KML format on server side.

        | Available keys are:
        | 'alias_tag' to identify KML tag to find sensor identifier (alias), 'name' by default;
        | 'id' for default sensor identifier, e.g., 'id': '0';
        | 'val_tag' to identify KML tag where server should find sensor value at the given moment of time, ('description' by default), e.g., val_tag: 'value';
        | 'val' for default sensor value at the given moment of time, 'null' by default;
        | 'ms_tag' to identify KML tag with a timestamp to use with the KML record, e.g., ms_tag: 'TimeStamp';
        | 'ms_attr' to identify attribute of the 'placemark' KML tag with a timestamp to use with the KML record, e.g., ms_attr: 'id';
        | 'ns' for default timestamp (nanosecond) of the sent data, e.g., 'ns': 1421299624000000000.

        All these records are used in case when server cannot derive such information
        (id, timestamp, value, etc.) from fields of sent KML data set. Use of 'ms_tag' and 'ms_attr' options
        is mutually exclusive, 'ms_tag' has priority if both options are given.

        Please note that if several data points in the KML data set miss sensor id and
        timestamp information, the server will use identical default id/timestamp values
        for all such points. Since only one data point can be stored for each pair of
        (sensor identifier, timestamp), only one data point from such data set will be
        actually stored as the result of the collision.

        :param content: KML/KMZ data to send
        :param default_params: additional parameters of the request with default geo-information values
        """
        return self.send_kml_data(open(filepath).read(), default_params)

    def send_kml_data(self, content, default_params):
        """Uploads data from sensors to server in Keyhole Markup Language (KML/KMZ) format.

        Additional parameters may hold several key-value records with predefined names to
        fill possible gaps in geo-information in KML format on server side.

        Please consult send_kml_file() function description for a list of available keys and
        additional comments.

        :param content: KML/KMZ data to send
        :param default_params: additional parameters of the request with default geo-information values
        """
        return self.kml_query(content, default_params)

    def send_events_data_chunked(self, time_series):
        """Uploads data to server using the chunked transfer encoding.

        :param time_series: content generator
        """
        return self._send_chunked_data('events', time_series)

    def _chunked_data(self, mode, data_iterator):
        for data in data_iterator:
            if isinstance(data, tuple):
                (app_key, data) = data
            else:
                app_key = None
            yield self._send_data_content(mode, data, app_key)

    def _send_chunked_data(self, mode, data_generator):
        return self.call_method_chunked('setData', self._chunked_data(mode, data_generator), args={'mode': mode})

    def _send_data(self, mode, data):
        return self.call_method('setData', self._send_data_content(mode, data), args={'mode': mode})

    def _send_data_content(self, mode, data, app_key = None):
        content = {
            'method': 'setData',
            'context': mode,
            'key': app_key or self.app_key,
            'opts': [],
            'params': data
        }
        if self.app_key is None or self.app_key == '':
            content['adminkey'] = self.admin_key
        return content

    def ping(self, timeout = None):
        """Sync ping of the data ingestion service responsible for the given Application Key.

           Server responses with 1 or with an error message if the service is unavailable.
           Please see description of ping_streaming_service() function for additional details.

        :param timeout: either maximum number of milliseconds to wait, or 'infinity'
        """
        return self._ping('events', timeout)

    def _ping(self, mode, timeout = None):
        p = {'timeout': timeout} if timeout == 'infinity' or\
                                    (isinstance(timeout, int) and timeout > 0) else {}
        method = 'ping'
        content = {
            'method': method,
            'context': mode,
            'key': self.app_key,
            'params': p
        }
        return self.call_method(method, content, args={'mode': mode})

    def cmd_events(self, args):
        """Reserved for internal use.

        :param args: command arguments
        """
        return self._cmd('events', args)

    def _cmd(self, mode, args):
        method = 'cmd_ext'
        content = {
            'method': method,
            'context': mode,
            'key': self.app_key,
            'params': args
        }
        return self.call_method(method, content, args={'mode': mode})

    def query(self, script, keep_order=False, stream=False):
        """The same as events_query(script, ver=2)
        """
        return self.events_query(script, keep_order=keep_order, ver=2, stream=stream)

    def async_query(self, script, keep_order=False, stream=False):
        """The same as async_events_query(script, ver=2)
        """
        return self.async_events_query(script, keep_order=keep_order, ver=2, stream=stream)

    def events_query(self, script, keep_order=False, ver=1, stream=False):
        """Queries 'events' sensor data from server using a query language syntax.

           The Script argument is a string, containing one or more query language
           (QL) statments. Syntax requires a semicolon at the end of each QL statement.

           Returned value depends on script content and can be either json/text sensor
           data for SELECT statement, or result of evaluation of other query statments.

           Mode of querying (streaming or events), as well as application keys to use,
           can be switched inside the script using query language statements.

        :param script: query language script content
        :param keep_order: use OrderedDict to store data in response
        :param ver: version of Query Language (1 or 2; 1 is default)
        :param stream: True if server is allowed to send query response as a stream
                       in json-seq format (https://tools.ietf.org/html/rfc7464)
        """
        return self.ql_query(script, args={
            'mode': 'events',
            'keep_order': keep_order,
            'ver': ver,
            'stream': stream})

    def async_events_query(self, script, keep_order=False, ver=1, stream=False):
        """Asynchronously queries 'events' sensor data from server using a query language syntax.

           The Script argument is a string, containing one or more query language
           (QL) statments. Syntax requires a semicolon at the end of each QL statement.

           Returned value depends on script content and can be either json/text sensor
           data for SELECT statement, or result of evaluation of other query statments.

           Mode of querying (streaming or events), as well as application keys to use,
           can be switched inside the script using query language statements.

        :param script: query language script content
        :param keep_order: use OrderedDict to store data in response
        :param ver: version of Query Language (1 or 2; 1 is default)
        :param stream: True if server is allowed to send query response as a stream
                       in json-seq format (https://tools.ietf.org/html/rfc7464)
        """
        return self.ql_query(script, args={
            'mode': 'events',
            'async': True,
            'keep_order': keep_order,
            'ver': ver,
            'stream': stream})

    def get_stored(self, uuid):
        """Queries data, which were stored after delayed execution of the query.

        :param uuid: identifier of the stored data, as returned in details of the
                     response with notification about delayed execution
        """
        return self.delayed_query(uuid, args={'mode': 'results'})

    def get_messages(self):
        """Queries TimeEngine for Error/Warning diagnostic messages about possible
           problems which could happen while data storing and indexing if a user
           has defined a list of indexes/incremental aggregation methods and this
           list does not conform with the actual data sent to the TimeEngine service.
        """
        return self.delayed_query('', args={'mode': 'result_events'})

    ###########
    # Admin API

    def new_appkey(self, user_info, key_opts = None, suggest = None):
        """Creates a new application key. Requires an admin key.

        :param user_info: details of the created user of the application key
        :param key_opts: None or a list of new application key options
        :param suggest: None or suggested application key (user is able to select application key if it does not exist)
        """
        method = 'newApiKey'
        content = {
            'method': method,
            'params': {
                'adminkey': self.admin_key,
                'day_limit': -1,
                'user': user_info
        }}
        if isinstance(key_opts, list) or isinstance(key_opts, dict):
            content['params']['opts'] = key_opts
        if isinstance(suggest, str):
            content['params']['suggest'] = suggest
        return self.call_method(method, content)

    def get_or_create_appkey(self, app_key, user_info, key_opts = None):
        """Read secret key of existing application key or creates a new application key. Requires an admin key.

        Returns secret key if app key exists and belongs to the admin key that executes the request.
        Returns error if existing app key belongs to another admin key.
        Creates a new application key if there is no app key with such name.

        :param app_key: application key to read or create
        :param user_info: details of the created user of the application key
        :param key_opts: None or a list of new application key options
        """
        method = 'assureApiKey'
        content = {
            'method': method,
            'params': {
                'adminkey': self.admin_key,
                'day_limit': -1,
                'user': user_info
        }}
        key_opts = key_opts or {}
        if isinstance(key_opts, list):
            key_opts = {opt: True for opt in key_opts}
        if isinstance(key_opts, dict):
            key_opts['suggest'] = app_key
            content['params']['opts'] = key_opts
        return self.call_method(method, content)

    def delete_appkey(self, app_key, keep_data = None):
        """Deletes the application key. Requires an admin key.

           The administrator key must be the same key that was used to create the application key.

        :param app_key: application key to update
        :param keep_data: optional boolean value to keep data after application key deletion
        """
        return self._delete_appkey('deleteApiKey', app_key, keep_data)

    def _delete_appkey(self, method, app_key, keep_data):
        params = {
            'adminkey': self.admin_key,
            'key': app_key
        }
        if isinstance(keep_data, bool):
            params['keep_data'] = keep_data
        content = {
            'method': method,
            'params': params
        }
        return self.call_method(method, content)

    def new_adminkey(self, user_info):
        """Creates a new admin key. Requires an admin key with super-user rights.

        :param user_info: details of the created user
        """
        method = 'newAdminKey'
        p = {
            'adminkey': self.admin_key,
            'user': user_info
        }
        return self.call_method(method, {'method': method, 'params': p})

    def get_or_create_adminkey(self, admin_key, user_info):
        """Read secret key of existing admin key or creates a new admin key. Requires an admin key with super-user rights.

        Returns secret key if admin key exists, otherwise creates a new admin key.

        :param admin_key: admin key to read or create
        :param user_info: details of the created user
        """
        method = 'assureAdminKey'
        content = {
            'method': method,
            'params': {
                'adminkey': self.admin_key,
                'suggest': admin_key,
                'user': user_info
        }}
        return self.call_method(method, content)

    def delete_adminkey(self, adm_key_to_delete):
        """Deletes the admin key. Requires an admin key with super-user rights.

        :param app_key: application key to update
        """
        method = 'deleteAdminKey'
        content = {
            'method': method,
            'params': {
                'adminkey': self.admin_key,
                'key': adm_key_to_delete
        }}
        return self.call_method(method, content)

    ###############
    # Websocket API

    def ws_target_url(self, asyncv=None, def_app_key=None):
        """Build a target URL for websocket connection.

        :param async: None if async mode is not predefined, True for async mode, False otherwise
        :param def_app_key: set not null if the predefined application key must be set in administrative websocket connection
        """
        uri = self.ws_target_url0(asyncv, def_app_key)
        if uri is not None:
            uri = self.ws_base_url + uri
        return uri

    def ws_target_url0(self, asyncv, def_app_key):
        if self.app_key != '':
            async_str = '' if asyncv is None else '?async=1' if asyncv else '?async=0'
            return "api/v1/ws/%s%s" % (self.app_key, async_str)
        elif self.admin_key != '':
            if def_app_key is not None:
                async_str = '' if asyncv is None else '&async=1' if asyncv else '&async=0'
                return "api/v1/ws/%s?key=%s%s" % (self.admin_key, def_app_key, async_str)
            else:
                async_str = '' if asyncv is None else '?async=1' if asyncv else '?async=0'
                return "api/v1/ws/%s%s" % (self.admin_key, async_str)
        else:
            return None

    def ws_authorization_header(self, asyncv = None, def_app_key = None):
        """Build the authorization header for websocket connection.
        """
        if self.access_token:
            access_token_type = self.access_token_type if self.access_token_type else "Bearer"
            return 'authorization: %s %s' % (access_token_type, self.access_token)
        else:
            method = 'ws'
            user_key = self.app_key or self.admin_key
            uri = self.ws_target_url0(asyncv, def_app_key)
            payload_hash = hashlib.sha256(b'' if PY3 else '').hexdigest()
            signature = self.make_auth_content(uri, method, payload_hash, '', maybe_encode(user_key))
            return 'authorization: %s%s %s' % (MDTSDB_AUTH2, user_key, signature)

    def ws_recv(self, ws, stream = False):
        if stream:
            rm = []
            while True:
                r = ws.recv()
                if r == '\x1e\n':
                    return ''.join(rm)
                rm.append(r)
        return ws.recv()

    def ws_parse(self, resp, args={'keep_order': False, 'stream': False}):
        """Parse response received from websocket.

        :param resp: response to parse
        :param args: parse options:
            keep_order: use OrderedDict to store data in response
            stream: True if server is allowed to send query response as a stream
                    in json-seq format (https://tools.ietf.org/html/rfc7464)

        """
        is_seq = 'stream' in args and args['stream']
        try:
            if 'keep_order' in args and args['keep_order']:
                jp = lambda txt: json.loads(txt, object_pairs_hook=OrderedDict)
            else:
                jp = lambda txt: json.loads(txt)
            if is_seq:
                lines = resp.split('\x1E')
                return [self._parse_result(jp(line.strip()), len(line)) for line in lines[1:]]
            else:
                result = jp(resp)
                (ok, r) = self._parse_result(result, len(resp))
                req_id = result['id'] if 'id' in result else None
                return (ok, req_id, r)
        except ValueError:
            return [resp] if is_seq else resp
        return 'error', None, 'unexpected response'

    def ws_query(self, script, asyncv, ver=2, stream=False):
        """Build a frame to send to server using websocket connection to query sensor data
           using TimeEngine query language syntax.

        :param script: query language script content
        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        :param stream: True if server is allowed to send query response as a stream
                       in json-seq format (https://tools.ietf.org/html/rfc7464)
        """
        return self._ws_post_data('q', asyncv, {
            'q': script,
            'v': str(ver),
            'stream': 1 if stream else 0
        })

    def ws_send_events_data(self, time_series, asyncv):
        """The compatibility wrapper for :func:`~client.Mdtsdb.ws_insert`.
        """
        return self.ws_insert(time_series, asyncv)

    def ws_insert(self, time_series, asyncv):
        """Build a query frame to uploads data from sensors to server in the 'events' mode
           using websocket connection.

           See send_events_data_vector() for the detailed description of the method parameter.

        :param time_series: dictionary, mapping a sensor identifier to the sensor value
        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        """
        return self.ws_send_data(time_series, asyncv)

    def ws_send_data(self, time_series, asyncv):
        """Build a query frame to uploads data from sensors to server using websocket connection.

           See send_events_data_vector() and send_streaming_data_vector() for the detailed description
           of the method parameter.

        :param time_series: dictionary, mapping a sensor identifier to the sensor value
        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        """
        return self._ws_post_data('setData', asyncv, time_series)

    def ws_send_events_geo_data(self, payload):
        """Build a query frame to uploads geo-data in GeoJSON/TopoJSON/KML format to server.
           Only events mode is supported.

           Data swimline is determined by the application key.
           Payload is a string in either GeoJSON, TopoJSON or KML format.

        :param payload: string in GeoJSON, TopoJSON or KML format
        """
        return payload

    def ws_send_kml_data(self, kml_content, default_params, asyncv):
        """Build a query frame to uploads data to server in Keyhole Markup Language (KML/KMZ) format.

           Please see additional details in description of the send_kml_data() and send_kml_file() method.

        :param kml_content: sensor data in Keyhole Markup Language format
        :param default_params: additional parameters of the request with default geo-information values
        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        """
        if 'base64' in default_params and default_params['base64'] == 'true':
            q = base64.b64encode(kml_content)
        else:
            q = kml_content
        opts = {}
        for k in self.kml_keys:
            if k in default_params:
                opts[k] = default_params[k]
        return self._ws_post_data('setData', asyncv, {'q': q}, opts)

    def ws_ping(self, timeout = 'infinity', asyncv = None):
        """Build a query frame to ping the service for the application key.

        :param timeout: either maximum number of milliseconds to wait, or 'infinity'
        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        """
        p = {'timeout': timeout} if timeout == 'infinity' or\
                                    (isinstance(timeout, int) and timeout > 0) else {}

        return self._ws_post_data('ping', asyncv, p)

    def ws_get_messages(self, asyncv):
        """Build a request to query events diagnostic (offline) messages.

        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        """
        return self.ws_get_stored('', asyncv)

    def ws_get_stored(self, uuid, asyncv):
        """Build a request to query diagnostic (offline) messages or previously saved results of query execution.

        :param uuid: name of the API method to call
        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        """
        return self._ws_post_data('getResults', asyncv, {'uuid': uuid})

    def ws_new_appkey(self, user_info, key_opts = None, suggest = None):
        """Build a request creates a new application key. Requires an admin key.

        :param user_info: details of the created user of the application key
        :param key_opts: None or a list of new application key options
        :param suggest: None or suggested application key (user is able to select application key if it does not exist)
        """
        content = {
            'method': 'newApiKey',
            'params': {
                'adminkey': self.admin_key,
                'day_limit': -1,
                'user': user_info
        }}
        if isinstance(key_opts, list) or isinstance(key_opts, dict):
            content['params']['opts'] = key_opts
        if isinstance(suggest, str):
            content['params']['suggest'] = suggest
        return json.dumps(content, separators=(',',':'))

    def ws_get_or_create_appkey(self, app_key, user_info, key_opts = None):
        """Read secret key of existing application key or creates a new application key. Requires an admin key.

        Returns secret key if app key exists and belongs to the admin key that executes the request.
        Returns error if existing app key belongs to another admin key.
        Creates a new application key if there is no app key with such name.

        :param app_key: application key to read or create
        :param user_info: details of the created user of the application key
        :param key_opts: None or a list of new application key options
        """
        content = {
            'method': 'assureApiKey',
            'params': {
                'adminkey': self.admin_key,
                'day_limit': -1,
                'user': user_info
        }}
        key_opts = key_opts or {}
        if isinstance(key_opts, list):
            key_opts = {opt: True for opt in key_opts}
        if isinstance(key_opts, dict):
            key_opts['suggest'] = app_key
            content['params']['opts'] = key_opts
        return json.dumps(content, separators=(',',':'))

    def _ws_post_data(self, method, asyncv, params, opts = None):
        """Helper method to generalize websocket data expected from send-data api calls.

        :param method: name of the API method to call
        :param asyncv: None if asyncv mode is not predefined, True for asyncv mode, False otherwise
        :param params: request parameters (e.g., sensor data to send)
        :param opts: request options (e.g., upload properies of the KML sensor data)
        """
        if asyncv is not None:
            if opts is None:
                opts = {'async': 1 if asyncv else 0}
            else:
                opts['async'] = 1 if asyncv else 0
        content = {
            'method': method,
            'context': 'events',
            'key': self.app_key,
            'params': params
        }
        if opts is not None:
            content['opts'] = opts
        return json.dumps(content, separators=(',',':'))

#############################################################################
