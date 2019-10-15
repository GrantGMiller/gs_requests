from gs_requests import HTTPSession

session = HTTPSession()

session.auth = ('username', 'password')

resp = session.get('http://www.extron.com', proxies={
    'http': '172.17.16.79:3128',
    'https': '172.17.16.79:3128',
})

print('resp.text=', resp.text)
try:
    print('resp.json=', resp.json)
except Exception as e:
    print(e)
print('resp.raw=', resp.raw)