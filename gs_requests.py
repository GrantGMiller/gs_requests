'''
This module was writted to duplicate the functions of the python-requests package to run on GS.
'''

import urllib.request
import urllib.parse
import json as stdlib_json
import base64

from extronlib.system import ProgramLog, File

DEBUG = True
if DEBUG is False:
    print = lambda *a, **k: None  # disable print statements


class HTTPSession:
    def __init__(self):
        self._cookieHandler = urllib.request.HTTPCookieProcessor()
        self._opener = urllib.request.build_opener(self._cookieHandler)

        self._proxyHandler = None
        self._proxyAddress = None
        self._proxyPort = None
        self._auth = tuple()

        self._httpsHandler = None

        self.headers = {}

    def request(self, *a, **k):
        return self.Request(*a, **k)

    def Request(self, url, data=None, proxies=None, headers=None, method=None, params=None, json=None, verify=True,
                timeout=None):
        print(
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

            print('29 data=', data[:100], '...')

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
            print('67 url=', url)
            if not url.endswith('?'):
                url += '?'

            if isinstance(params, str):
                url += params
            elif isinstance(params, dict):
                url += urllib.parse.urlencode(params)
                print('74 url=', url)
        if headers:
            pass

        print('77 urllib.request.Request(url={}, method={}, data={}, headers={}'.format(
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

        print('97 url=', url)
        req = urllib.request.Request(url, method=method, data=data, headers=headers)

        print('100 req=', req.full_url, req.method, req.headers)
        resp = None
        try:
            resp = self._opener.open(req, timeout=timeout)
            print('resp.code=', resp.code)
            return Response(raw=resp.read(), code=resp.code)
        except Exception as e:
            print('79 Error', e, ', resp=', resp, e.args)
            if resp:
                return Response(raw=resp.read(), code=resp.code)
            else:
                try:
                    return Response(raw=e.read(), code=e.code)
                except Exception as e2:
                    print(e)
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
    def auth(self, authTuple):
        self._auth = authTuple
        username, password = authTuple
        headerValue = 'Basic {}'.format(
            base64.b64encode('{}:{}'.format(username, password).encode()).decode()
        )
        self.headers['Authorization'] = headerValue

    @property
    def cookies(self):
        return self._cookieHandler.cookiejar


class Session(HTTPSession):
    pass


class session(HTTPSession):
    pass


class Response:
    def __init__(self, raw, code):
        print('Response.__init__(', raw, code)
        self._raw = raw
        self._code = code
        self._headers = {}

    @property
    def raw(self):
        return self._raw

    def json(self):
        if isinstance(self._raw, bytes):
            raw = self._raw.decode()
        else:
            raw = self._raw

        return stdlib_json.loads(raw)

    @property
    def text(self):
        print('self._raw=', self._raw)
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
        return '<gs_requests.Response: code={}, headers={}>'.format(self._code, self._headers)


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
    s = Session()
    s.headers['testkey'] = 'testvalue'
    resp = s.get('https://www.extron.com')
    s.request('https://www.extron.com')
    print('resp.text=', resp.text)
    print('s.headers=', s.headers)
