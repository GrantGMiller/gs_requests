Extron Global Scripter blocks the popular "requests" library and does not allow for pip-installing python packages.

This module is meant to mimic its behavior, while being compatible with GS.

Swapping
========
If you already have code that works with requests.py, you can simply change your import statement from

::

    import requests

to

::

    import gs_requests as requests



Simple Usage
------------------

You can do simple get/post requests like so:

::

    import gs_requests as requests

    resp = requests.get('https://postman-echo.com/get?foo1=bar1&foo2=bar2')
    print('resp.ok=', resp.ok)
    print('resp.status_code=', resp.status_code)
    print('resp.reason=', resp.reason)
    print('resp.text=', resp.text)
    print('resp.json=', resp.json())

    resp = requests.get(
        url='https://postman-echo.com/get',
        params={'key1': 'value1', 'key2': 'value2'}
    )

    resp = requests.post(
        url='https://postman-echo.com/post',
        json={'key': 'value'}
    )
    print('resp.text=', resp.text)
    print('resp.json=', resp.json())

Sessions (Cookie Handling)
-----------------------------

::

    import gs_requests as requests

    session = requests.Session()

    resp = session.get('https://postman-echo.com/cookies/set?foo1=bar1&foo2=bar2')
    print('session.cookies=', session.cookies)

    resp = session.get('https://postman-echo.com/cookies/set?foo3=bar3&foo4=bar4')
    print('session.cookies=', session.cookies)



Basic Authentication
--------------------------

::

    import gs_requests as requests

    session = requests.Session()
    session.auth = ('postman', 'password')
    resp = session.get('https://postman-echo.com/basic-auth')
    print('resp.text=', resp.text)

Proxy
------------

::

    import gs_requests as requests

    session = requests.Session()

    resp = session.get(
        url='https://postman-echo.com/get?foo1=bar1&foo2=bar2',
        proxies={
            'https': 'https://192.168.254.254:3128',  # no proxy authentication
            'http': 'http://admin:password@192.168.254.254:3128',  # with proxy authentication
        })
    print('resp.text=', resp.text)

Self Signed Certificates
--------------------------------

Pass the verify=False parameter to ignore certificate validation errors.

::

    import gs_requests as requests

    session = requests.Session()
    resp = session.get('https://postman-echo.com/basic-auth', verify=False)
    print('resp.text=', resp.text)
