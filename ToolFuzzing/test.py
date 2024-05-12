from XSS import xssFuzz
from SQLi import scanSqlErrorBase

def main():
    # url = 'http://testphp.vulnweb.com/artists.php?artist=1'
    # url = 'http://testhtml5.vulnweb.com'
    url = input("Nhập vào url: ")
    scanSqlErrorBase.scan(url)
    xssFuzz.scan_xss(url)

if __name__ == '__main__':
    main()
