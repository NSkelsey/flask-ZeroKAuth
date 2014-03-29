import requests
import json
import random

from srp_client import Client

BASE = "http://127.0.0.1:5000"
HEADS = {'Content-Type': 'application/json', 'Accept': 'text/plain'}

def create_user(cli, password):
    uname = 'hickerman' + str(random.randint(0, 4**4**2))
    s, v = cli.establish(uname, password)      
    payload = {'credentials': {'s': s,'v': v}, 'username': uname}
    resp = requests.post(BASE + '/create', data=json.dumps(payload), headers=HEADS)
    print resp.text


def do_handshake(cli):
    uname, A = cli.compute_A()
    payload = json.dumps({'username': uname, 'A': A})
    resp = requests.post(BASE + '/handshake', data=payload, headers=HEADS)
    js = resp.json()
    s, B = js['s'], js['B']
    return (s, B)

def try_verify(cli):
    M1 = cli.generate_M1()
    payload = json.dumps({'username': cli.I, 'M1': M1})
    print M1
    resp = requests.post(BASE + '/verify', data=payload, headers=HEADS)
    try:
        js = resp.json()
        M2 = js['M2']
        cli.verify_M2(M2)
    except ValueError:
        import pprint
        pp = pprint.PrettyPrinter()
        print "="*50
        pp.pprint(cli.__dict__)
        print "="*50
        pass

    

if __name__ == '__main__':

    pw = "God this pw is so safe"
    print type(pw)
    cli = Client()

    create_user(cli, pw)

    s, B = do_handshake(cli)

    cli.compute_secret(pw, s, B)

    try_verify(cli)
