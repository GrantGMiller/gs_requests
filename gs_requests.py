'''
This module was writted to duplicate the functions of the python-requests package to run on GS.
More info here: https://github.com/GrantGMiller/gs_requests
'''

import urllib.request
import urllib.parse
import json as stdlib_json
import base64

try:
    from extronlib.system import ProgramLog, File
except Exception as e:
    print(e)

try:
    import gs_requests_ntlm as request_ntlm
except Exception as e:
    print('Warning: could not import gs_requests_ntlm:', e)


class HTTPSession:
    def __init__(self, debug=False):
        self._cookieHandler = urllib.request.HTTPCookieProcessor()
        self._opener = urllib.request.build_opener(self._cookieHandler)

        self._proxyHandler = None
        self._proxyAddress = None
        self._proxyPort = None
        self._auth = tuple()

        self._httpsHandler = None

        self.headers = {}
        self.debug = debug

    def print(self, *a, **k):
        if self.debug:
            print(*a, **k)

    def request(self, *a, **k):
        return self.Request(*a, **k)

    def Request(self, url, data=None, proxies=None, headers=None, method=None, params=None, json=None, verify=True,
                timeout=None):
        self.print(
            'gs_requests.Request(url={}, data={}, proxies={}, headers={}, method={}, params={}, json={}, verify={}, timeout={}'.format(
                url, data, proxies, headers, method, params, json, verify, timeout
            ))

        headers = headers or self.headers
        method = method.upper() if method else 'GET'

        if data:
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
                headers.update({'content-type': 'application/x-www-form-urlencoded'})

            elif isinstance(data, str):
                data = data.encode()

            elif isinstance(data, File):
                data = data.read()

            else:
                raise TypeError('Unrecognized type "{}".'.format(type(data)))

            self.print('29 data=', data[:1000], '...')

        if json:
            data = stdlib_json.dumps(json, indent=2, sort_keys=True).encode()
            headers.update({'content-type': 'application/json'})

        if proxies:
            '''
            proxies should be in the form
            {"http": "http://admin:extron@192.168.68.109:8080", "https": "https://admin:extron@192.168.68.109:8080"}
            or
            {"http": "http://192.168.68.109:8080", "https": "https://192.168.68.109:8080"}
            '''

            self._proxyHandler = urllib.request.ProxyHandler(proxies)
            self._opener.add_handler(self._proxyHandler)

        if params:
            self.print('67 url=', url)
            if not url.endswith('?'):
                url += '?'

            if isinstance(params, str):
                url += params
            elif isinstance(params, dict):
                url += urllib.parse.urlencode(params)
                self.print('74 url=', url)
        if headers:
            pass

        self.print('77 urllib.request.Request(url={}, method={}, data={}, headers={}'.format(
            url, method, data, headers
        ))

        if verify is False:
            from extronlib.system import GetUnverifiedContext
            context = GetUnverifiedContext()
            if self._httpsHandler is None:
                self._httpsHandler = urllib.request.HTTPSHandler(context=context)
                # for some reason UnverifiedContext only works with urllib.request.build_opener and not with add_handler
                self._opener = urllib.request.build_opener(self._httpsHandler)
                if self._proxyHandler:
                    self._opener.add_handler(self._proxyHandler)
                if self._cookieHandler:
                    self._opener.add_handler(self._cookieHandler)
        else:
            context = None

        self.print('97 url=', url)
        req = urllib.request.Request(url, method=method, data=data, headers=headers)

        self.print('100 req=', req.full_url, req.method, req.headers)
        resp = None
        try:
            resp = self._opener.open(req, timeout=timeout)
            self.print('resp.code=', resp.code)
            return Response(
                raw=resp.read(),
                code=resp.code,
                headers=resp.headers,
                debug=self.debug,
            )
        except Exception as e:
            self.print('79 Error', e, ', resp=', resp, e.args)
            if resp:
                return Response(raw=resp.read(), code=resp.code, headers=resp.headers)
            else:
                try:
                    return Response(raw=e.read(), code=e.code, headers=e.headers)
                except Exception as e2:
                    self.print(e)
                    return Response(raw=str(e).encode(), code=400)

    def get(self, *a, **k):
        k['method'] = 'GET'
        resp = self.Request(*a, **k)
        return resp

    def post(self, *a, **k):
        k['method'] = 'POST'
        resp = self.Request(*a, **k)
        return resp

    def put(self, *a, **k):
        k['method'] = 'PUT'
        resp = self.Request(*a, **k)
        return resp

    def patch(self, *a, **k):
        k['method'] = 'PATCH'
        resp = self.Request(*a, **k)
        return resp

    @property
    def auth(self):
        return self._auth

    @auth.setter
    def auth(self, authObj):
        if isinstance(authObj, tuple):
            # assume basic auth
            self._auth = authObj
            username, password = authObj
            headerValue = 'Basic {}'.format(
                base64.b64encode('{}:{}'.format(username, password).encode()).decode()
            )
            self.headers['Authorization'] = headerValue

        # NTLM
        elif isinstance(authObj, request_ntlm.HttpNtlmAuth):
            urllib.request.HTTPPasswordMgrWithDefaultRealm()
            passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            passman.add_password('', '', authObj.username, authObj.password)
            ntlmHandler = request_ntlm.HTTPNtlmAuthHandler(passman)
            self._opener.add_handler(ntlmHandler)

    @property
    def cookies(self):
        return self._cookieHandler.cookiejar


class Session(HTTPSession):
    pass


class session(HTTPSession):
    pass


class Response:
    def __init__(self, raw, code, headers=None, debug=False):
        self.debug = debug
        self.print('Response.__init__(', raw, code)
        self._raw = raw
        self._code = code

        if headers and not isinstance(headers, dict):
            # headers is probably of type http.client.HTTPMessage
            # convert it to a dict
            d = {}
            for header in str(headers).splitlines():
                split = header.split(': ', 1)
                if len(split) == 2:
                    key, value = split
                    if key not in d:
                        d[key] = value
                    elif key in d:
                        d[key] += '; {}'.format(value)
            headers = d

        self.headers = headers or {}

    def print(self, *a, **k):
        if self.debug:
            print(*a, **k)

    @property
    def raw(self):
        return self._raw

    def json(self):
        if isinstance(self._raw, bytes):
            raw = self._raw.decode()
        else:
            raw = self._raw

        try:
            return stdlib_json.loads(raw)
        except Exception as e:
            return None  # this request is not a JSON string

    @property
    def text(self):
        self.print('self._raw=', self._raw)
        return self._raw.decode()

    @property
    def content(self):
        return self._raw.decode()

    @property
    def status_code(self):
        return self._code

    @property
    def ok(self):
        return 200 <= self._code < 300

    @property
    def reason(self):
        return self._code

    def __str__(self):
        return '<gs_requests.Response: code={}, headers={}>'.format(self._code, str(self.headers).encode())


def get(*a, **k):
    tempSession = HTTPSession()
    return tempSession.get(*a, **k)


def post(*a, **k):
    tempSession = HTTPSession()
    return tempSession.post(*a, **k)


def patch(*a, **k):
    return HTTPSession().patch(*a, **k)


def request(*a, **k):
    return HTTPSession().request(*a, **k)


class Exceptions:
    RequestException = IOError


exceptions = Exceptions()


class Auth:
    def __init__(self):
        self.username = None
        self.password = None

    def HTTPBasicAuth(self, username, password):
        self.username = username
        self.password = password
        return self.username, self.password


auth = Auth()

if __name__ == '__main__':
    # s = Session()
    # s.headers['testkey'] = 'testvalue'
    # resp = s.get('https://www.extron.com')
    # s.request('https://www.extron.com')
    # print('resp.text=', resp.text)
    # print('s.headers=', s.headers)

    s = Session(debug=True)
    s.auth = ('SVC-Exch-ExtronRoomA@stadtwerke-bonn.ads', '!<7<]OumhA\"Bo#6fX{7')

    url = 'https://owa.stadtwerke-bonn.de/EWS/Exchange.asmx'
    body = '''<ns0:Envelope xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:ns2="http://schemas.microsoft.com/exchange/services/2006/messages"><ns0:Header><ns1:RequestServerVersion Version="Exchange2007_SP1" /><ns1:ExchangeImpersonation><ns1:ConnectingSID><ns1:PrimarySmtpAddress>Ex_res_sandkaule3.ogtestraum@stadtwerke-bonn.de</ns1:PrimarySmtpAddress></ns1:ConnectingSID></ns1:ExchangeImpersonation></ns0:Header><ns0:Body><ns2:FindItem Traversal="Shallow"><ns2:ItemShape><ns1:BaseShape>Default</ns1:BaseShape><ns1:AdditionalProperties><ns1:FieldURI FieldURI="item:DateTimeCreated" /><ns1:FieldURI FieldURI="calendar:IsRecurring" /><ns1:FieldURI FieldURI="calendar:Organizer" /><ns1:FieldURI FieldURI="calendar:Duration" /><ns1:FieldURI FieldURI="item:Sensitivity" /></ns1:AdditionalProperties></ns2:ItemShape><ns2:CalendarView EndDate="2021-12-21T16:11:49.763267" StartDate="2021-12-14T16:11:49.763267" /><ns2:ParentFolderIds><ns1:DistinguishedFolderId Id="calendar"><ns1:Mailbox><ns1:EmailAddress>Ex_res_sandkaule3.ogtestraum@stadtwerke-bonn.de</ns1:EmailAddress></ns1:Mailbox></ns1:DistinguishedFolderId></ns2:ParentFolderIds></ns2:FindItem></ns0:Body></ns0:Envelope>'''

    resp = s.post(url, body, verify=False)
    print('resp.headers=', resp.headers)
