import urllib.request
import urllib.parse
import http.cookiejar
import re

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 1. Login to get cookie
login_html = opener.open('http://127.0.0.1:8000/login').read().decode()
csrf = re.search(r'name="csrf_token" value="([^"]+)"', login_html).group(1)

login_data = urllib.parse.urlencode({
    'username_or_email': 'footprint_admin_demo',
    'password': 'FootprintIQ-Demo-2026!',
    'csrf_token': csrf,
    'next': ''
}).encode()
opener.open(urllib.request.Request('http://127.0.0.1:8000/auth/login', data=login_data))

# 2. Get /admin/tools
tools_html = opener.open('http://127.0.0.1:8000/admin/tools').read().decode()

for line in tools_html.splitlines():
    if any(k in line.lower() for k in ['nmap', 'executable', '7.9', 'ready', 'greenbone']):
        print(' ', line.strip())

