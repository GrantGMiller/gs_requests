import urllib.request
import urllib.parse
import json

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

    def get(self, url, data=None, proxies=None, headers=None, method=None):
        '''

        :param url:
        :param data: dict or None
        :param proxies:
        :return:
        '''
        self._DoRequest(url, data=data, proxies=proxies, headers=headers, method='GET')

    def _DoRequest(self, url, data=None, proxies=None, headers=None, method=None):
        print('gs_requests._DoRequest(', url, data, proxies, headers, method)
        headers = headers or dict()

        if data:
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
                headers.update({'content-type': 'application/x-www-form-urlencoded'})
            elif isinstance(data, str):
                data = data.encode()

            print('29 data=', data)

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

        req = urllib.request.Request(url, method=method, data=data, headers=headers)
        self._printObj(req)
        try:
            resp = self._opener.open(req)
            return Response(raw=resp.read())
        except Exception as e:
            self._printObj(e)
            raise e

    @staticmethod
    def _printObj(obj):
        try:
            print('69 obj.info()=', obj.info())
        except:
            pass

        for item in dir(obj):
            try:
                print(item, '=', getattr(obj, item))
            except:
                print(item)


    def post(self, url, data=None, proxies=None, headers=None, method=None):
        resp = self._DoRequest(url, data=data, proxies=proxies, headers=headers, method='POST')
        return resp

    @property
    def auth(self):
        return self._auth

    @auth.setter
    def auth(self, authTuple):
        self._auth = authTuple
        username, password = authTuple
        authHandler = urllib.request.HTTPBasicAuthHandler()
        authHandler.add_password(None, '/', username, password)
        self._opener.add_handler(authHandler)


class Response:
    def __init__(self, raw):
        self._raw = raw

    @property
    def raw(self):
        return self._raw

    def json(self):
        return json.loads(self._raw)

    @property
    def text(self):
        return self._raw.decode()

    @property
    def content(self):
        return self._raw.decode()


def get(*a, **k):
    tempSession = HTTPSession()
    return tempSession.get(*a, **k)


def post(*a, **k):
    tempSession = HTTPSession()
    return tempSession.post(*a, **k)
