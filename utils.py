import random
from binascii import hexlify
import os
import hashlib


def randbits(n=512):
    """input number of bits and get back that many random bits as a long"""
    return long(random.SystemRandom().getrandbits(n))


def _hash(*args):
    """returns a long of the encoded params
    which are either strings or int (converted to hex)"""
    def upd(h, val):
        typ = type(val)
        assert typ == int or typ == str or typ == long
        if typ == int:
            h.update(hex(val)[2:])
        elif typ == long:
            h.update(hex(val)[2:-1])
        else:
            h.update(val)
        return h
    # Just call str on input then pass into our hash function
    _hex = reduce(upd, args, hashlib.sha256()).hexdigest()
    return int(_hex, 16)

def group_constants():
    """Returns the defined group constants for our implementation"""
    N = """EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"""
    g = 2
    print "N before: ", N
    N = int(N, 16)
    k = _hash(N, g)
    print "N after: ", N
    print "k after: ", k
    return (N, g, k)


if __name__ == '__main__':
    print _hash('doge')
    assert _hash('doge') == 89062479946239498583283658615240302315455651348145828341129845111945473878501
    N, g, k = group_constants()
    assert k == 80910912930494333589932475365044532708556454027074488358013717185805616192253 

