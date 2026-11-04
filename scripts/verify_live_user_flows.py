import urllib.request
import urllib.parse
import http.cookiejar
import re

def test_full_browser_session():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    
    # 1. GET /login to get CSRF token and cookie
    login_page = opener.open('http://127.0.0.1:8000/login').read().decode('utf-8')
    match = re.search(r'name="csrf_token" value="([^"]+)"', login_page)
    assert match, 'CSRF token not found in login page'
    csrf_token = match.group(1)
    print(f'Obtained CSRF token: {csrf_token[:12]}...')
    
    # 2. POST /auth/login as admin
    admin_data = urllib.parse.urlencode({
        'username_or_email': 'footprint_admin_demo',
        'password': 'FootprintIQ-Demo-2026!',
        'csrf_token': csrf_token,
        'next': ''
    }).encode()
    req = urllib.request.Request(
        'http://127.0.0.1:8000/auth/login',
        data=admin_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    res = opener.open(req)
    print(f'Admin login redirected to: {res.geturl()} [HTTP {res.getcode()}]')
    
    # Check admin tools page
    tools_html = opener.open('http://127.0.0.1:8000/admin/tools').read().decode('utf-8')
    nmap_ready = 'READY' in tools_html
    greenbone_unconf = 'NOT CONFIGURED' in tools_html
    print(f'Admin Tools: Nmap READY={nmap_ready} | Greenbone NOT CONFIGURED={greenbone_unconf}')
    
    # Check admin investigators page
    inv_mgmt_html = opener.open('http://127.0.0.1:8000/admin/investigators').read().decode('utf-8')
    has_pending = 'Pending Approvals' in inv_mgmt_html
    has_active = 'Active &amp; Approved Investigators' in inv_mgmt_html or 'Active & Approved Investigators' in inv_mgmt_html
    has_toggle = '/admin/investigators/' in inv_mgmt_html and ('deactivate' in inv_mgmt_html or 'activate' in inv_mgmt_html)
    print(f'Admin Investigators Page: Length={len(inv_mgmt_html)} bytes | Pending Approvals={has_pending} | Active Table={has_active} | Toggle Actions={has_toggle}')
    
    # 3. GET /login for investigator
    cj2 = http.cookiejar.CookieJar()
    opener2 = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj2))
    login_page2 = opener2.open('http://127.0.0.1:8000/login').read().decode('utf-8')
    match2 = re.search(r'name="csrf_token" value="([^"]+)"', login_page2)
    csrf_token2 = match2.group(1)
    
    # POST /auth/login as investigator
    inv_data = urllib.parse.urlencode({
        'username_or_email': 'footprint_investigator_demo',
        'password': 'FootprintIQ-Demo-2026!',
        'csrf_token': csrf_token2,
        'next': ''
    }).encode()
    req2 = urllib.request.Request(
        'http://127.0.0.1:8000/auth/login',
        data=inv_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    res2 = opener2.open(req2)
    print(f'Investigator login redirected to: {res2.geturl()} [HTTP {res2.getcode()}]')
    
    # Check /investigations
    inv_page = opener2.open('http://127.0.0.1:8000/investigations').read().decode('utf-8')
    has_campaigns = 'Investigation Campaigns' in inv_page
    print(f'Investigator /investigations: Length={len(inv_page)} bytes | Campaigns Present={has_campaigns}')
    
    # Check /findings
    findings_page = opener2.open('http://127.0.0.1:8000/findings').read().decode('utf-8')
    has_findings = 'Security Findings' in findings_page
    print(f'Investigator /findings: Length={len(findings_page)} bytes | Findings Present={has_findings}')
    
    # Check an investigation detail workspace as admin
    admin_workspace = opener.open('http://127.0.0.1:8000/investigations/inv-0520a3e0').read().decode('utf-8')
    has_admin_ws = 'Live E2E Verification Campaign' in admin_workspace
    print(f'Admin Workspace /investigations/inv-0520a3e0: Length={len(admin_workspace)} bytes | Title Present={has_admin_ws}')

    # Check an investigation detail workspace as investigator (owned campaign)
    workspace = opener2.open('http://127.0.0.1:8000/investigations/inv-7e04aea2e6').read().decode('utf-8')
    has_workspace = 'TAJ' in workspace
    print(f'Investigator Workspace /investigations/inv-7e04aea2e6: Length={len(workspace)} bytes | Title Present={has_workspace}')

if __name__ == '__main__':
    test_full_browser_session()
