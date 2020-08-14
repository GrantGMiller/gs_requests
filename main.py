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
print('resp.text=', resp.text)
print('resp.json=', resp.json())

resp = requests.post(
    url='https://postman-echo.com/post',
    json={'key': 'value'}
)
print('resp.text=', resp.text)
print('resp.json=', resp.json())

#####################################################################

session = requests.Session()

resp = session.get('https://postman-echo.com/cookies/set?foo1=bar1&foo2=bar2')
print('session.cookies=', session.cookies)

resp = session.get('https://postman-echo.com/cookies/set?foo3=bar3&foo4=bar4')
print('session.cookies=', session.cookies)

#####################################################################

session = requests.Session()
session.auth = ('postman', 'password')
resp = session.get('https://postman-echo.com/basic-auth')
print('resp.text=', resp.text)

####################################################################

session = requests.Session()
try:
    resp = session.get(
        url='https://postman-echo.com/get?foo1=bar1&foo2=bar2',
        proxies={
            'https': 'https://172.17.8.73:3128',  # no proxy authentication
            'http': 'http://admin:extron@172.17.8.74:3128',  # with proxy authentication
        },
        timeout=2,
    )
    print('resp.text=', resp.text)
except Exception as e:
    print(e)

##################################################################

session = requests.Session()
session.auth = ('admin', 'extron')
resp = session.get('https://expired.badssl.com/', verify=False)
print('resp.text=', resp.text)

###################################################################

print('end main.py')