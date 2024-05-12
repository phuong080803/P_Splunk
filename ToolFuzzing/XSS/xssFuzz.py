from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
from WebConfig import web

f = open(r"C:\Users\PBUG\Downloads\scriptsKTLT\XSS\xss.txt", "r")
payloads = []
for pay in f.readlines():
    payloads.append(pay.strip())

def scan_form_in_url(url, cookies=None):
    html = web.getHTML(url, cookies=cookies)

    if html:
        soup = BeautifulSoup(html.text, 'html.parser')
        forms = soup.find_all('form', method=True)

        for form in forms:
            try:
                action = form['action']
            except KeyError:
                action = url

            try:
                method = form['method'].lower().strip()
            except KeyError:
                method = 'get'

            i = 0
            for payload in payloads:
                keys = {}
                for key in form.find_all(["input", "textarea"]):
                    try:
                        if key['type'] == 'submit':
                            try:
                                keys.update({key['name']: key['name']})
                            except Exception as e:
                                keys.update({key['value']: key['value']})
                        else:
                            keys.update({key['name']: payload})
                    except Exception as e:
                        print('Internal error: ' + str(e))
                        if method.lower().strip() == 'get':
                            try:
                                keys.update({key['name']: payload})
                            except KeyError as e:
                                print('Internal error: ' + str(e))
                final_url = urljoin(url, action)
                if method.lower().strip() == 'get':
                    req_html = web.getHTML(final_url, method=method.lower(), params=keys, cookies=cookies)
                    if payload in req_html.text:
                        print(' Vulnerable detected in url/form :' + final_url)
                        print(payload)
                        break
                elif method.lower().strip() == 'post':
                    req_html = web.getHTML(final_url, method=method.lower(), data=keys, cookies=cookies)
                    if payload in req_html.text:
                        print('[-]Vulnerable detected in url/form :' + final_url)
                        print('==>Payload: ' + payload)
                        break
def scan_in_a_url(url, cookies=None):
    queries = urlparse(url).query
    if queries != '':
        for payload in payloads:
            parser_query = []
            for query in queries.split("&"):
                parser_query.append(query[0:query.find('=') + 1])
            new_query = "&".join([param + payload for param in parser_query])
            final_url = url.replace(queries, new_query, 1)
            req_1 = web.getHTML(final_url, verify=False)

            encode_query = urlencode({x: payloads for x in parse_qs(queries)})
            final_encode_url = url.replace(queries, encode_query, 1)
            req_2 = web.getHTML(final_encode_url)

            if req_1:
                if payload in req_1.text or payload in req_2.text:
                    print('[-]Vulnerable detected in url :' + final_url)
                    print('==>Payload: ' + payload)
                    return True
        return False
    return False

def scan_xss(url, method=2, cookies=None):
    print("-------------XSS----------------")
    scan_in_a_url(url)
    scan_form_in_url(url)
    print("-"*41)