#!/usr/local/bin/python
import re, sys, requests, hashlib
from pwn import *

HOST = sys.argv[1]
PORT = int(sys.argv[2])

EXPECT = {
        '/': '<html><body><h1>Authenticator</h1><a href="/gen"><h2>generate</h2></a><a href="/list"><h2>list</h2></a></body></html>',
        '/enroll': 'not found',
        '/list': '<html><body><h1>Authenticator</h1><hr></body></html>',
        }

def build_req(method='GET', path='/', data='', **kwargs):
    raw = '''%s %s HTTP/1.1\r\n''' % (method, path)
    data += '&'.join('%s=%s' % (k, v) for k, v in kwargs.iteritems())
    raw += 'Content-Length: %d\r\n' % (len(data))
    raw += 'Connection: keep-alive\r\n'
    raw += '\r\n'
    raw += data
    return raw

def recv_http(r):
    d = r.recvuntil('Content-Length: ')
    l = r.recvuntil('\r\n')
    n = int(l.strip())
    d += l
    while not d.endswith('\r\n\r\n'):
        d += r.recvn(1)
    d += r.recvn(n)
    return d

b64 = lambda s: s.encode('base64').replace('\n', '').replace('=', '')

def parse_cookie(d):
    return d.split('session=')[1].split(';')[0].decode('base64')

class InvalidState(Exception):
    pass

def check_pages():
    for k, v in EXPECT.iteritems():
        print 'checking GET %s' % k
        r = requests.get('http://%s:%d%s' % (HOST, PORT, k))
        assert r.content == v, InvalidState('unexpected %s %r %r' % (k, v, r.content))

def check_info():
    print 'checking GET /info'
    EXPECT = {
            'ACCEPT': '*/*',
#            'USER-AGENT': 'python-requests/2.22.0',
            'ACCEPT-ENCODING': 'gzip,deflate',
            'CONNECTION': 'keep-alive',
            'HOST': '%s:%d' % (HOST, PORT),
            }
    r = requests.get('http://%s:%d/info' % (HOST, PORT))
    d = re.findall(r'env: {([^}]*)}', r.content)[0]
    d = d.replace('gzip, deflate', 'gzip,deflate') # hack
    for t in d.split(', '):
        k, v = t.split(': ')
        if k[1:-1] == 'USER-AGENT':
            continue
        assert EXPECT[k[1:-1]] == v[1:-1], InvalidState('/info %s %s'% (k, v))

def check_keep_alive():
    print 'checking keep alive'
    r = remote(HOST, PORT)
    d = ''
    for k in sorted(EXPECT.keys()):
        r.send(build_req(path=k))
        t = recv_http(r)
        d += ''.join(sorted(t.split('\r\n')))
    sig = hashlib.md5(d).hexdigest()
    ANSWER = '0c9c7c91dbeb58f4f47564fe350908f2'
    assert sig == ANSWER, InvalidState('not alive', sig)
    r.close()

def check_session():
    print 'checking cookie consitency'
    s = requests.Session()
    a = ''
    for i in xrange(5):
        k = randoms(10)
        v = randoms(10)
        a += '<hr>Label: %s<br/>Secret: %s<br/>Code: INVALID' % (k, v)
        r = s.post('http://%s:%d/enroll' % (HOST, PORT), data={'label': k, 'secret': v})
        assert a in r.content, InvalidState('broken session')

def check_http():
    print 'checking http headers'
    url = 'http://%s:%d/info' % (HOST, PORT)
    headers = {randoms(10).upper(): randoms(10) for _ in xrange(5)}
    d = requests.get(url, headers=headers).content
    for k, v in headers.iteritems():
        t = '"%s": "%s"' % (k, v)
        assert t in d, InvalidState('env', t)

    print 'checking post data'
    charset = map(chr, list(set(range(256)).difference({ord('&'),
        ord('=')})))
    params = {randoms(randint(4, 256), charset): randoms(randint(4, 256),
        charset) for _ in xrange(randint(5, 10))}
    raw = '&'.join('%s=%s' % i for i in params.iteritems())
    d = requests.get(url, data=raw).content
    assert ', '.join(map(str, map(ord, raw))) in d, InvalidState('data')
    for k, v in params.iteritems():
        assert '%s: %s' % (map(ord, k), map(ord, v)) in d, InvalidState('data')

def check_unserialize():
    url = 'http://%s:%d/info' % (HOST, PORT)
    EXPECT = {
            'N;': 'NULL',
            'b:1;': 'bool(true)',
            'i:111111111111111111;': 'int(111111111111111111)',
            'a:0:{}': 'array(0) {}',
            's:4:"abcd";': 'string(4) "abcd"',
            'a:1:{s:1:"s";i:1;}': 'array(1) {["s"]\n=>int(1)\n}',
            'a:3:{i:0;i:1;i:2;i:3;i:4;i:5;}': 'array(3) {["0"]\n=>int(1)\n["2"]\n=>int(3)\n["4"]\n=>int(5)\n}',
            'a:2:{i:0;i:1337;r:2;i:2;}': 'array(2) {["0"]\n=>int(1337)\n["1337"]\n=>int(2)\n}'
            }
    for k, v in EXPECT.iteritems():
        print 'checking unserialize("%s")' % k
        r = requests.get(url, data={'session': b64(k)})
        assert v in r.content, InvalidState('unserialize', k, r.content)

if __name__ == '__main__':
    try:
        check_pages()
        check_info()
        check_keep_alive()
        check_session()
        check_http()
        check_unserialize()
        sys.exit(0)
    except Exception as e:
        # print 'PUBLIC: %s' % e
        sys.exit(1)
