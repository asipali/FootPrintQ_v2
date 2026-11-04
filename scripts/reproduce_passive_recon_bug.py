import urllib.request
import urllib.parse
import http.cookiejar
import re

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 1. Login
login_page = opener.open('http://127.0.0.1:8000/login').read().decode('utf-8')
csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', login_page).group(1)

inv_data = urllib.parse.urlencode({
    'username_or_email': 'footprint_investigator_demo',
    'password': 'FootprintIQ-Demo-2026!',
    'csrf_token': csrf_token,
    'next': ''
}).encode()
login_resp = opener.open(urllib.request.Request('http://127.0.0.1:8000/auth/login', data=inv_data))

# 2. Get post-login CSRF token from investigation workspace page
ws_html = opener.open('http://127.0.0.1:8000/investigations/inv-7e04aea2e6').read().decode('utf-8')
match = re.search(r'name="csrf_token" value="([^"]+)"', ws_html)
assert match, 'Post-login CSRF token not found'
post_login_csrf = match.group(1)

# 3. Post passive recon with unapproved target
post_data = urllib.parse.urlencode({
    'target': 'unauthorized.example',
    'csrf_token': post_login_csrf
}).encode()
req = urllib.request.Request(
    'http://127.0.0.1:8000/investigations/inv-7e04aea2e6/recon/passive',
    data=post_data,
    headers={'Accept': 'text/html,application/xhtml+xml', 'Content-Type': 'application/x-www-form-urlencoded'}
)
resp = opener.open(req)
print('Redirected to:', resp.geturl())
print('Response code:', resp.getcode())
page_text = resp.read().decode('utf-8')
print('Error banner in workspace:', 'Target reconnaissance authorization denied' in page_text or 'Notice:' in page_text)
