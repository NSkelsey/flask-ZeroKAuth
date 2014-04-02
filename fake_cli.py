import requests
import json
import random

from srp_client import Client
from utils import _hex

BASE = "http://127.0.0.1:5000"
HEADS = {'Content-Type': 'application/json', 'Accept': 'text/plain'}



def create_user(cli, uname, password):
    s, v = cli.establish(password)      
    payload = {'s': _hex(s),'v': _hex(v), 'username': uname}
    print payload
    resp = requests.post(BASE + '/create', data=json.dumps(payload), headers=HEADS)
    print resp.text
    return resp


def do_handshake(cli, uname):
    A = cli.compute_A(uname)
    payload = json.dumps({'username': uname, 'A': _hex(A)})
    resp = requests.post(BASE + '/handshake', data=payload, headers=HEADS)
    js = resp.json()
    s, B = long(js['s'], 16), long(js['B'], 16)
    return (s, B)

def try_verify(cli):
    M1 = cli.generate_M1()
    payload = json.dumps({'username': cli.I, 'M1': _hex(M1)})
    resp = requests.post(BASE + '/verify', data=payload, headers=HEADS)
    try:
        js = resp.json()
        M2 = long(js['M2'], 16)
        return resp.cookies
    except ValueError:
        import pprint
        pp = pprint.PrettyPrinter()
        print "="*50
        pp.pprint(cli.__dict__)
        print "="*50
        return False


COOKS = None

if __name__ == '__main__':

    cli = Client()

    username = 'jajajaja' + str(random.randint(0,5000))
    pw = "My safe PW"
    resp = create_user(cli, username, pw)
    if resp.status_code != 200:
        print 'died at creation'
        import sys; sys.exit()

    s, B = do_handshake(cli, username)

    cli.compute_secret(pw, s, B)

    out = try_verify(cli)
    COOKS = out
    if out:
        print "User Successfully authenticated"
        resp = requests.get(BASE + '/admin', cookies=out)
        print resp.text
        print "LOGGING OUT"
        resp = requests.get(BASE + '/logout', cookies=resp.cookies)
        print "TRYING RESTRICTED SPOT"
        resp = requests.get(BASE + '/admin',  cookies=resp.cookies)
        print resp.text
    else:
        print "Verification failed"
