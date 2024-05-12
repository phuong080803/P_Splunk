from urllib.parse import urlparse, urljoin, urlencode, parse_qs

from bs4 import BeautifulSoup
from SQLi import sqlerrors
from WebConfig import web

with open("sql.txt", "r") as f:
    payloads = f.readlines()
print(payloads)

def scan_sql_error_base_in_form(url):
    html = web.getHTML(url)

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
            for payload in payloads:
                payload = payload.strip()
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
                        print("Internal error " + str(e))

                final_url = urljoin(url, action)
                if method == 'get':
                    source = web.getHTML(final_url, method=method, params=keys)
                    vulnerable, db = sqlerrors.check(source.text)
                    if vulnerable and (db is not None):
                        print('[-]Vulnerable detected in form: ' + final_url)
                        print('==>Payload: ' + payload)
                        break
                elif method == 'post':
                    source = web.getHTML(final_url, method=method, data=keys)
                    vulnerable, db = sqlerrors.check(source.text)
                    if vulnerable and (db is not None):
                        print('[-]Vulnerable detected in form: ' + final_url)
                        print('==>Payload: ' + payload)
                        break

def scan_sql_error_base_in_url(url):
    queries = urlparse(url).query
    if queries != '':
        for payload in payloads:
            payload = payload.strip()
            parser_query = []
            for query in queries.split("&"):
                parser_query.append(query[0:query.find('=') + 1])
            new_query = "&".join([param + payload for param in parser_query])
            final_url = url.replace(queries, new_query, 1)

            encode_query = urlencode({x: payload for x in parse_qs(queries)})
            final_encode_url = url.replace(queries, encode_query, 1)
            res = web.getHTML(final_encode_url)

            if res:
                vulnerable2, db2 = sqlerrors.check(res.text)
                if vulnerable2 and (db2 is not None):
                    print('[-]Vulnerable detected in url/href: ' + final_url)
                    print('==>Payload: ' + payload)
                    return True
    else:
        return False
    return False

def scan(url):
    print("-------------SQLinjection----------------")
    scan_sql_error_base_in_url(url)
    scan_sql_error_base_in_form(url)
    print("-"*41)