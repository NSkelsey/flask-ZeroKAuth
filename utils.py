import random
from binascii import hexlify
import os
import hashlib


def randbits(n=512):
    """input number of bits and get back that many random bits"""
    return random.SystemRandom().getrandbits(n)


def _hash(*args):
    """returns a long of the encoded params
    which are either strings or int (converted to hex)"""
    def upd(h, val):
        typ = type(val)
        #print typ,':', val
        assert typ == int or typ == str or typ == long
        if typ == int or typ == long:
            h.update(hex(val))
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
    N = int(N, 16)
    k = _hash(N, g)
    return (N, g, k)


if __name__ == '__main__':
    assert _hash('doge') == 28088777564775743774903282203516146997506500108233848107224846866863036396859L
    N, g, k = group_constants()
    assert k == 80910912930494333589932475365044532708556454027074488358013717185805616192253 

