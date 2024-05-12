

import requests
from urllib.error import HTTPError, URLError, ContentTooShortError
from urllib.parse import urlparse
import socket
from WebConfig import useragents

"""
    Mình xây dựng module này để thiết lập request nó có các sử lý ngoại lệ và trả về False nếu request hỏng
    còn nếu không thì nó sẽ trả về giá trị để mình phân tích
"""


def getHTML(url, lastUrl=False, method=None, headers=None, data=None, params=None, verify=None, cookies=None):
    if method is None:
        method = 'get'

    if not (url.startswith("http://") or url.startswith("https://")):
        url = 'http://' + url

    if headers is None:
        headers = useragents.get()

    html = None

    try:
        if method == 'get':
            req = requests.get(url, headers=headers, cookies=cookies, params=params, verify=verify, timeout=2000)
            # Log.info('url : ' + str(req.url))
        else:
            req = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=2000)
            # Log.info('url : ' + req.url)
    except requests.exceptions.HTTPError as http:
        print('something wrong with http request')
    except requests.exceptions.InvalidURL as urlError:
        print('something wrong with url')
    except requests.exceptions.Timeout:
        print('time out')
    except requests.exceptions.TooManyRedirects:
        print('URL was bad and try a different one')
    except Exception as e:
        print("error " + str(e))
    else:
        html = req

    if html:
        return html

    return False