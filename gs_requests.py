import urllib.request
import urllib.parse
import json

DEBUG = False
if DEBUG is False:
    print = lambda *a, **k: None  # disable print statements


class HTTPSession:
    def __init__(self):
        cookieHandler = urllib.request.HTTPCookieProcessor()
        self._opener = urllib.request.build_opener(cookieHandler)

        self._proxyAddress = None
        self._proxyPort = None
        self._auth = tuple()

    def get(self, url, data=None, proxies=None):
        '''

        :param url:
        :param data: dict or None
        :param proxies:
        :return:
        '''
        if data:
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
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

        resp = self._opener.open(url, data=data)
        return Response(raw=resp.read())

    def post(self, *a, **k):
        self.get(*a, **k)

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
