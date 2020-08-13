'''
This module was writted to duplicate the functions of the python-requests package to run on GS.
'''

import urllib.request
import urllib.parse
import json
from extronlib.system import GetUnverifiedContext
import base64

DEBUG = True
if DEBUG is False:
    print = lambda *a, **k: None  # disable print statements


class HTTPSession:
    def __init__(self):
        cookieHandler = urllib.request.HTTPCookieProcessor()
        self._opener = urllib.request.build_opener(cookieHandler)

        self._proxyAddress = None
        self._proxyPort = None
        self._auth = tuple()

        self.headers = {}

    def request(self, *a, **k):
        return self.Request(*a, **k)

    def Request(self, url, data=None, proxies=None, headers=None, method=None, params=None, json=None, verify=True):
        print(
            'gs_requests.Request(url={}, data={}, proxies={}, headers={}, method={}, params={}, json={}, verify={}'.format(
                url, data, proxies, headers, method, params, json, verify
            ))
        headers = headers or self.headers

        if data:
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
                headers.update({'content-type': 'application/x-www-form-urlencoded'})
            elif isinstance(data, str):
                data = data.encode()

            print('29 data=', data)

        if json:
            data = json.dumps(json, indent=2, sort_keys=True)

        if proxies:
            proxyString = list(proxies.values())[0]
            self._proxyAddress = proxyString.split(':')[0].split('://')[-1]
            try:
                self._proxyPort = int(proxyString.split(':')[1])
            except:
                self._proxyPort = None

            proxyHandler = urllib.request.ProxyHandler({
                'http': 'http://{}:{}'.format(
                    self._proxyAddress,
                    self._proxyPort or '3128',  # default proxies port is 3128
                ),
                'https': 'https://{}:{}'.format(
                    self._proxyAddress,
                    self._proxyPort or '3128',  # default proxies port is 3128
                ),
            })
            self._opener.add_handler(proxyHandler)

        if params:
            url += '?'
            if isinstance(params, str):
                url += params
            elif isinstance(params, dict):
                url += urllib.parse.urlencode(params)

        if headers:
            pass

        print('urllib.request.Request(url={}, method={}, data={}, headers={}'.format(
            url, method, data, headers
        ))

        if verify is False:
            context = GetUnverifiedContext()
            httpsHandler = urllib.request.HTTPSHandler(context=context)
            self._opener.add_handler(httpsHandler)
        else:
            context = None

        req = urllib.request.Request(url, method=method, data=data, headers=headers, )
        # self._printObj(req)
        print('req=', req.full_url, req.method, req.headers)
        resp = None
        try:
            resp = self._opener.open(req)
            print('resp.code=', resp.code)
            self.headers.update(dict(resp.headers))
            return Response(raw=resp.read(), code=resp.code)
        except Exception as e:
            print('79 Error', e, ', resp=', resp)
            # self._printObj(e)
            if resp:
                return Response(raw=resp.read(), code=resp.code)
            else:
                # if len(e.args) == 0:
                #     pass
                #     #raise e
                # else:
                    return Response(raw=e.read(), code=e.code)

    @staticmethod
    def _printObj(obj):
        try:
            print('69 obj.info()=', obj.info())
            print('obj.reason=', obj.reason)
            print('obj.read=', obj.read())
        except:
            print('69 except obj=', obj)

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


class Session(HTTPSession):
    pass


class session(HTTPSession):
    pass


class Response:
    def __init__(self, raw, code):
        print('Response.__init__(', raw, code)
        self._raw = raw
        self._code = code

    @property
    def raw(self):
        return self._raw

    def json(self):
        if isinstance(self._raw, bytes):
            raw = self._raw.decode()
        else:
            raw = self._raw
        return json.loads(raw)

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


def get(*a, **k):
    tempSession = HTTPSession()
    return tempSession.get(*a, **k)


def post(*a, **k):
    tempSession = HTTPSession()
    return tempSession.post(*a, **k)


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
